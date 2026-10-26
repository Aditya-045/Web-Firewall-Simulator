"""
dossier_reader.py -- read-only loader and integrity verifier for
aegis_dossier.json (SRS 3.6).

The verification deliberately mirrors aegis_firewall.MerkleDossier so the
GUI can independently confirm what the firewall claims:
  entry hash = sha256(json.dumps(entry_without_hash, sort_keys=True))
  merkle root = pairwise sha256(left + right) up the tree, duplicating the
                last node on odd levels; an empty log's root is 64 zeros.
This module never writes to the file.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Optional

EMPTY_ROOT = "0" * 64


def _sha(val: str) -> str:
    return hashlib.sha256(val.encode("utf-8")).hexdigest()


def compute_entry_hash(entry: dict) -> str:
    body = {k: v for k, v in entry.items() if k != "hash"}
    return _sha(json.dumps(body, sort_keys=True))


def compute_merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return EMPTY_ROOT
    level = list(hashes)
    while len(level) > 1:
        if len(level) % 2 != 0:
            level.append(level[-1])
        level = [_sha(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
    return level[0]


@dataclass
class DossierResult:
    ok: bool = False                 # file was read and parsed
    error: str = ""
    logs: list[dict] = field(default_factory=list)
    stored_root: str = ""
    computed_root: str = ""
    bad_entries: list[int] = field(default_factory=list)   # ids whose own hash doesn't match
    root_matches: bool = False

    @property
    def intact(self) -> bool:
        return self.ok and not self.bad_entries and self.root_matches


def load_and_verify(path: str) -> DossierResult:
    res = DossierResult()
    if not os.path.isfile(path):
        res.error = "No dossier file yet (it is created when the firewall logs its first event)."
        return res
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        # A read that races the firewall's rewrite can see a half-written
        # file; the caller simply retries on the next poll.
        res.error = f"Could not read dossier: {e}"
        return res

    logs = data.get("logs", [])
    res.ok = True
    res.logs = logs
    res.stored_root = data.get("root", "")

    stored_hashes = []
    for i, entry in enumerate(logs):
        stored = entry.get("hash", "")
        stored_hashes.append(stored)
        if compute_entry_hash(entry) != stored:
            res.bad_entries.append(entry.get("id", i + 1))

    res.computed_root = compute_merkle_root(stored_hashes)
    res.root_matches = (res.computed_root == res.stored_root)
    return res
