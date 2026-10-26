"""
auth_db.py -- SecureGateway Authentication & Authorization Store
==================================================================
Owned exclusively by the firewall (aegis_firewall.py). server.py never
imports this module -- the backend application server has no notion
of identity; it only ever talks to the trusted firewall process.

Stores:
  - user credentials (Argon2id-hashed) + global RWXD permission flags
  - admin credentials (Argon2id-hashed), separate table, always full
    control -- admin accounts never carry RWXD flags to check
  - a durable login-attempt audit trail, used for lockout and kept
    independent of the in-memory MerkleDossier (which resets on
    firewall restart)

No ML model lives here or is trained here -- lockout and permission
checks are plain rule-based logic against SQLite, by design.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHash

IST = timezone(timedelta(hours=5, minutes=30))

# Anchored to this file's own directory, NOT the process's current working
# directory. Without this, running `python bootstrap_admin.py` from one
# folder and `python aegis_firewall.py` from another would silently create
# and read two different SQLite files, and grants would appear to "not
# work" for a completely different reason than the stale-session-cache bug
# fixed above -- worth ruling out categorically rather than trusting every
# launch script to `cd` to the right place first.
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aegis_auth.db")

# ---------------------------------------------------------------------
# Lockout policy (adjust freely -- these are the only two knobs)
# ---------------------------------------------------------------------
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15

# Applies to both the "users" and "admins" tables.
PERM_COLUMNS = {"r": "can_read", "w": "can_write", "x": "can_execute", "d": "can_destruct"}
PERM_KEYS = {"can_read": "read", "can_write": "write", "can_execute": "execute", "can_destruct": "destruct"}

_hasher = PasswordHasher()
_lock = threading.Lock()  # serializes SQLite access; every write path uses a single connection per call


def _now_iso() -> str:
    return datetime.now(IST).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


@contextmanager
def _db():
    with _lock:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()


def init_db():
    """Creates tables if they don't already exist. Safe to call on every
    firewall startup."""
    with _db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                can_read INTEGER NOT NULL DEFAULT 1,
                can_write INTEGER NOT NULL DEFAULT 0,
                can_execute INTEGER NOT NULL DEFAULT 0,
                can_destruct INTEGER NOT NULL DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT,
                created_at TEXT NOT NULL,
                last_login TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_type TEXT NOT NULL,
                username TEXT NOT NULL,
                source_ip TEXT,
                success INTEGER NOT NULL,
                timestamp TEXT NOT NULL
            )
        """)


# ---------------------------------------------------------------------
# Password hashing (Argon2id -- current OWASP-recommended default)
# ---------------------------------------------------------------------
def hash_password(plain: str) -> str:
    return _hasher.hash(plain)


def verify_password(stored_hash: str, plain: str) -> bool:
    try:
        _hasher.verify(stored_hash, plain)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


# ---------------------------------------------------------------------
# Result wrapper -- every public function below returns one of these
# ---------------------------------------------------------------------
class AuthResult:
    __slots__ = ("ok", "reason", "data")

    def __init__(self, ok: bool, reason: str = "", data: dict | None = None):
        self.ok = ok
        self.reason = reason
        self.data = data or {}


def _row_to_permissions(row: sqlite3.Row) -> dict:
    return {
        "read": bool(row["can_read"]),
        "write": bool(row["can_write"]),
        "execute": bool(row["can_execute"]),
        "destruct": bool(row["can_destruct"]),
    }


def _is_locked(row: sqlite3.Row) -> bool:
    if not row["locked_until"]:
        return False
    try:
        locked_until = datetime.fromisoformat(row["locked_until"])
    except ValueError:
        return False
    return datetime.now(IST) < locked_until


def _record_attempt(conn: sqlite3.Connection, actor_type: str, username: str, source_ip: str, success: bool):
    """Writes on the CALLER's already-open connection/transaction. Must not
    open a second connection here: SQLite's own file-level locking (not
    just our Python-level lock) would deadlock against the transaction
    _login() already has open."""
    conn.execute(
        "INSERT INTO login_attempts (actor_type, username, source_ip, success, timestamp) "
        "VALUES (?, ?, ?, ?, ?)",
        (actor_type, username, source_ip, int(success), _now_iso())
    )


# ---------------------------------------------------------------------
# Registration (self-service, users only -- admins are bootstrapped
# separately via bootstrap_admin.py, never over the wire)
# ---------------------------------------------------------------------
def register_user(username: str, password: str) -> AuthResult:
    username = (username or "").strip()
    if not username or not password:
        return AuthResult(False, "Username and password are required.")
    with _db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            return AuthResult(False, "Username already taken.")
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, hash_password(password), _now_iso())
        )
    return AuthResult(True, "Registered. Default privileges: read-only.")


def register_admin(username: str, password: str) -> AuthResult:
    """Only ever called from bootstrap_admin.py -- there is no client-facing
    ADMIN_REGISTER message."""
    username = (username or "").strip()
    if not username or not password:
        return AuthResult(False, "Username and password are required.")
    with _db() as conn:
        existing = conn.execute("SELECT id FROM admins WHERE username = ?", (username,)).fetchone()
        if existing:
            return AuthResult(False, "Admin username already exists.")
        conn.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, hash_password(password), _now_iso())
        )
    return AuthResult(True, "Admin account created.")


# ---------------------------------------------------------------------
# Login (shared logic for both users and admins)
# ---------------------------------------------------------------------
def login_user(username: str, password: str, source_ip: str = "unknown") -> AuthResult:
    return _login(username, password, source_ip, table="users", actor_type="user")


def login_admin(username: str, password: str, source_ip: str = "unknown") -> AuthResult:
    return _login(username, password, source_ip, table="admins", actor_type="admin")


def _login(username: str, password: str, source_ip: str, table: str, actor_type: str) -> AuthResult:
    username = (username or "").strip()
    if not username or not password:
        return AuthResult(False, "Username and password are required.")

    with _db() as conn:
        row = conn.execute(f"SELECT * FROM {table} WHERE username = ?", (username,)).fetchone()

        if row is None:
            # Deliberately identical message to a wrong-password failure --
            # don't leak whether a username exists.
            _record_attempt(conn, actor_type, username, source_ip, False)
            return AuthResult(False, "Invalid username or password.")

        if _is_locked(row):
            _record_attempt(conn, actor_type, username, source_ip, False)
            return AuthResult(False, f"Account locked until {row['locked_until']} (IST). Ask an admin to unlock it.")

        if not verify_password(row["password_hash"], password):
            new_failed = row["failed_attempts"] + 1
            locked_until = None
            if new_failed >= MAX_FAILED_ATTEMPTS:
                locked_until = (datetime.now(IST) + timedelta(minutes=LOCKOUT_DURATION_MINUTES)).isoformat()
            conn.execute(
                f"UPDATE {table} SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (0 if locked_until else new_failed, locked_until, row["id"])
            )
            _record_attempt(conn, actor_type, username, source_ip, False)
            if locked_until:
                return AuthResult(False, f"Too many failed attempts. Locked for {LOCKOUT_DURATION_MINUTES} minutes.")
            remaining = MAX_FAILED_ATTEMPTS - new_failed
            return AuthResult(False, f"Invalid username or password. {remaining} attempt(s) left before lockout.")

        conn.execute(
            f"UPDATE {table} SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
            (_now_iso(), row["id"])
        )
        _record_attempt(conn, actor_type, username, source_ip, True)

        data = {"username": row["username"]}
        if table == "users":
            data["permissions"] = _row_to_permissions(row)
        return AuthResult(True, "Login successful.", data)


# ---------------------------------------------------------------------
# Admin-facing account management (used by handle_admin_command)
# ---------------------------------------------------------------------
def set_permission(username: str, perm_letter: str, value: bool) -> AuthResult:
    column = PERM_COLUMNS.get((perm_letter or "").lower())
    if not column:
        return AuthResult(False, "Unknown permission letter. Use r, w, x, or d.")
    with _db() as conn:
        row = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            return AuthResult(False, f"User '{username}' not found.")
        conn.execute(f"UPDATE users SET {column} = ? WHERE username = ?", (int(value), username))
    verb = "Granted" if value else "Revoked"
    return AuthResult(True, f"{verb} '{perm_letter.upper()}' for '{username}'.")


def get_permissions(username: str) -> AuthResult:
    with _db() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row:
            return AuthResult(False, f"User '{username}' not found.")
        return AuthResult(True, data=_row_to_permissions(row))


def unlock_account(username: str, actor_type: str = "user") -> AuthResult:
    table = "users" if actor_type == "user" else "admins"
    with _db() as conn:
        row = conn.execute(f"SELECT id FROM {table} WHERE username = ?", (username,)).fetchone()
        if not row:
            return AuthResult(False, f"{actor_type.capitalize()} '{username}' not found.")
        conn.execute(f"UPDATE {table} SET failed_attempts = 0, locked_until = NULL WHERE username = ?", (username,))
    return AuthResult(True, f"{actor_type.capitalize()} '{username}' unlocked.")


def list_users() -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT username, can_read, can_write, can_execute, can_destruct, "
            "locked_until, last_login FROM users ORDER BY username"
        ).fetchall()
        return [dict(r) for r in rows]
