"""
command_classifier.py -- Shared R / W / X / D command classification
=======================================================================
Single source of truth for mapping a raw command string to the RWXD
permission tier it requires. Used by aegis_firewall.py's permission
gate, enforced *before* a command is ever forwarded to the backend.

Tiers:
  READ     SELECT / SHOW / DESCRIBE / EXPLAIN
  WRITE    INSERT / UPDATE / REPLACE
  DESTRUCT DROP / DELETE / ALTER / TRUNCATE / CREATE / GRANT / REVOKE / CALL
           (the highest tier -- schema- or privilege-altering statements)
  EXECUTE  anything that doesn't match SQL at all: generic system-style
           commands (git, pip, systemctl, cd, python, ls, cat, ...)

server.py keeps its own copy of the read/destructive split for its
defense-in-depth check on the backend side; this module is the
firewall-side gate that decides whether a command is forwarded at all.
"""

import re

READ_LEAD = re.compile(r'^\s*(select|show|desc|describe|explain)\b', re.IGNORECASE)
WRITE_LEAD = re.compile(r'^\s*(insert|update|replace)\b', re.IGNORECASE)
DESTRUCT_LEAD = re.compile(r'^\s*(drop|delete|alter|truncate|create|grant|revoke|call)\b', re.IGNORECASE)

READ = "read"
WRITE = "write"
EXECUTE = "execute"
DESTRUCT = "destruct"

LETTER = {READ: "R", WRITE: "W", EXECUTE: "X", DESTRUCT: "D"}


def classify(command: str) -> str:
    """Returns one of READ, WRITE, EXECUTE, DESTRUCT for a raw command string."""
    cmd = (command or "").strip()
    if READ_LEAD.match(cmd):
        return READ
    if WRITE_LEAD.match(cmd):
        return WRITE
    if DESTRUCT_LEAD.match(cmd):
        return DESTRUCT
    # Anything not recognizably SQL is treated as a generic system-style
    # command requiring execute privilege.
    return EXECUTE


def is_sql(command: str) -> bool:
    cmd = (command or "").strip()
    return bool(READ_LEAD.match(cmd) or WRITE_LEAD.match(cmd) or DESTRUCT_LEAD.match(cmd))
