"""
config_manager.py -- Prototype 1 configuration + pinned working directory
============================================================================
Everything the four launched processes need to agree on (which
aegis_auth.db / aegis_dossier.json they share, which ports they use, which
DB engine server.py should use) is centralized here as one plain,
JSON-serializable dataclass. Per the SRS:
  - Real MySQL credentials are NEVER persisted to disk -- only entered
    per-session in the Server Configuration dialog.
  - db_engine defaults to "mock" (sandboxed, no real MySQL required).
"""

from __future__ import annotations

import dataclasses
import json
import os
from typing import Optional

CONFIG_FILENAME = "waf_simulator_config.json"

# Files auth_db.py / aegis_firewall.py expect to find in the shared
# working directory. Their absence isn't fatal (they're created on first
# run) but its presence tells us we're pointed at a real, already-used
# SecureGateway project folder rather than an empty one.
EXPECTED_BACKEND_FILES = (
    "aegis_firewall.py", "server.py", "client.py", "admin_console.py",
    "auth_db.py", "protocol.py", "command_classifier.py", "bootstrap_admin.py",
)


@dataclasses.dataclass
class SimulatorConfig:
    working_dir: str = ""

    firewall_host: str = "127.0.0.1"
    firewall_port: int = 8080

    backend_host: str = "127.0.0.1"
    backend_port: int = 9091

    # "mock" (default, sandboxed SQLite, no real MySQL touched) or "mysql"
    db_engine: str = "mock"
    mysql_host: str = "127.0.0.1"
    mysql_port: int = 3306
    mysql_user: str = "root"
    mysql_database: str = "brics"
    # Deliberately NOT a dataclass field: the MySQL password is held only
    # in memory for the running session (see MainWindow._mysql_password)
    # and must never be written into this config file.

    def script_path(self, filename: str) -> str:
        return os.path.join(self.working_dir, filename)

    def validate_working_dir(self) -> list[str]:
        """Returns a list of human-readable problems; empty list = OK."""
        problems = []
        if not self.working_dir or not os.path.isdir(self.working_dir):
            problems.append("Working directory is not set or does not exist.")
            return problems
        missing = [f for f in EXPECTED_BACKEND_FILES if not os.path.isfile(self.script_path(f))]
        if missing:
            problems.append(
                "The following expected backend files were not found in this folder: "
                + ", ".join(missing)
            )
        return problems

    # -----------------------------------------------------------------
    # Persistence (non-secret fields only)
    # -----------------------------------------------------------------
    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "SimulatorConfig":
        known = {f.name for f in dataclasses.fields(cls)}
        filtered = {k: v for k, v in d.items() if k in known}
        return cls(**filtered)

    def save(self, path: Optional[str] = None) -> str:
        path = path or self._default_config_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return path

    @classmethod
    def load(cls, path: Optional[str] = None) -> "SimulatorConfig":
        path = path or cls._default_config_path_static()
        if not os.path.isfile(path):
            return cls()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)

    def _default_config_path(self) -> str:
        return self._default_config_path_static()

    @staticmethod
    def _default_config_path_static() -> str:
        home = os.path.expanduser("~")
        return os.path.join(home, ".waf_simulator", CONFIG_FILENAME)
