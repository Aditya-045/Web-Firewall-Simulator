"""
admin_status.py -- turns the Admin Terminal's raw output into structured
counts for the status bar (SRS 3.7), by parsing what the unmodified
admin_console.py already prints. Chunk-safe: output arrives in arbitrary
pieces, so text is buffered and only complete blocks are parsed.

Recognised blocks (formats defined by aegis_firewall.handle_admin_command):

  status     -> a JSON object printed with indent=2:
                {"system_active":..., "internal_user_states": {user: strikes},
                 "legitimate_count": n, "illegitimate_count": n}
  listusers  -> "[ADMIN] Registered users:" followed by one line per user:
                "<name>  R1 W0 X0 D0  strikes=0/2  [LOCKED]"
                terminated by admin_console's 60-dash separator line.
                "[ADMIN] No registered users." is the empty case.

This is a parser only. It never sends anything; the caller decides when
to write 'status' / 'listusers' to the admin console.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional

LOGIN_OK_MARKER = "[ADMIN-AUTH] Login successful"
_SEPARATOR = "-" * 60

# Top-level JSON only: nested closing braces are indented, so "\n}" at
# column 0 can only be the end of the outer object.
_STATUS_RE = re.compile(r'\{\s*"system_active".*?\n\}', re.DOTALL)
_USER_LINE_RE = re.compile(
    r"^(?P<name>\S+)\s+R(?P<r>\d) W(?P<w>\d) X(?P<x>\d) D(?P<d>\d)\s+"
    r"strikes=(?P<strikes>\d+)/2(?P<locked>\s+\[LOCKED\])?\s*$",
    re.MULTILINE,
)
_BUFFER_LIMIT = 40000


@dataclass
class AdminStats:
    system_active: Optional[bool] = None
    allowed: Optional[int] = None          # legitimate_count
    blocked: Optional[int] = None          # illegitimate_count
    warned: Optional[int] = None           # users with exactly 1 strike
    terminated: Optional[int] = None       # users with >= 2 strikes
    registered: Optional[int] = None       # from listusers
    locked: Optional[int] = None           # from listusers

    def merge(self, other: "AdminStats"):
        for k, v in other.__dict__.items():
            if v is not None:
                setattr(self, k, v)

    def summary(self) -> str:
        def f(v):
            return "?" if v is None else str(v)
        return (f"Users: {f(self.registered)} registered, {f(self.warned)} warned, "
                f"{f(self.terminated)} terminated, {f(self.locked)} locked  |  "
                f"Allowed: {f(self.allowed)}  Blocked: {f(self.blocked)}")


class AdminOutputParser:
    def __init__(self):
        self._buf = ""
        self.logged_in = False
        self.stats = AdminStats()

    def reset(self):
        self._buf = ""
        self.logged_in = False
        self.stats = AdminStats()

    def feed(self, text: str) -> list[str]:
        """Feeds a raw output chunk. Returns a list of event names that
        occurred: 'login', 'status', 'users' (so the caller can refresh UI)."""
        events: list[str] = []
        self._buf = (self._buf + text)[-_BUFFER_LIMIT:]

        if not self.logged_in and LOGIN_OK_MARKER in self._buf:
            self.logged_in = True
            events.append("login")

        # ---- status JSON: take the LAST complete object, then consume it
        last = None
        for m in _STATUS_RE.finditer(self._buf):
            last = m
        if last is not None:
            try:
                data = json.loads(last.group(0))
                states = data.get("internal_user_states", {}) or {}
                self.stats.merge(AdminStats(
                    system_active=bool(data.get("system_active")),
                    allowed=int(data.get("legitimate_count", 0)),
                    blocked=int(data.get("illegitimate_count", 0)),
                    warned=sum(1 for v in states.values() if v == 1),
                    terminated=sum(1 for v in states.values() if v >= 2),
                ))
                events.append("status")
            except (ValueError, TypeError):
                pass
            self._buf = self._buf[last.end():]

        # ---- listusers block: needs the closing separator to be complete
        idx = self._buf.rfind("[ADMIN] Registered users:")
        empty_idx = self._buf.rfind("[ADMIN] No registered users.")
        if idx != -1 and (empty_idx == -1 or idx > empty_idx):
            end = self._buf.find(_SEPARATOR, idx)
            if end != -1:
                block = self._buf[idx:end]
                rows = list(_USER_LINE_RE.finditer(block))
                self.stats.merge(AdminStats(
                    registered=len(rows),
                    locked=sum(1 for r in rows if r.group("locked")),
                ))
                events.append("users")
                self._buf = self._buf[end + len(_SEPARATOR):]
        elif empty_idx != -1:
            end = self._buf.find(_SEPARATOR, empty_idx)
            if end != -1:
                self.stats.merge(AdminStats(registered=0, locked=0))
                events.append("users")
                self._buf = self._buf[end + len(_SEPARATOR):]

        return events
