"""
server.py -- SecureGateway Backend Application Server
=======================================================
This is the real backend service that AegisFirewall (aegis_firewall.py)
protects. It never talks to the outside world directly: it only accepts
connections forwarded internally by the firewall/gateway after traffic
has already been classified as legitimate (GREEN) or warned-but-allowed
(ORANGE), and after the RWXD permission gate has already approved it.

Responsibilities:
  - Execute READ (SELECT/SHOW/DESC/EXPLAIN) and WRITE (INSERT/UPDATE/
    REPLACE) SQL for real against the BRICS MySQL database (tables:
    gdp_data, brics_debt_trade).
  - Refuse DESTRUCT-tier SQL (DROP/DELETE/ALTER/TRUNCATE/CREATE/GRANT/
    REVOKE/CALL) unconditionally, regardless of firewall-level 'D'
    permission. This is a deliberate, hardcoded second safety net --
    the firewall's RWXD gate is one trust boundary; this is another,
    independent one, on the assumption that the gate could someday
    have a bug and a live production database should not depend on
    a single checkpoint to stay intact.
  - Execute a small allowlist of harmless shell commands for real
    (echo, cat, ls, pwd, whoami, date, wc), each confined to a
    sandbox directory for anything that touches the filesystem.
    'cd' is virtual: no real shell persists between requests, so a
    per-user "current directory" is tracked in memory here and applied
    to subsequent sandboxed commands.
  - Return realistic *simulated* output for every other system-style
    command (git, pip, systemctl, python, ...) -- nothing is actually
    executed for those, exactly as before.
  - Independently re-classify every INTERNAL command with the same
    shared command_classifier the firewall used, and refuse to run
    anything if its own classification disagrees with what the
    firewall declared. This is the "double safety net": a bug or a
    tampered payload that tries to sneak a destructive statement
    through under a 'read' or 'execute' label gets caught here too,
    not just at the gate.

Run this BEFORE starting aegis_firewall.py, in its own terminal:
    python server.py
"""

import asyncio
import json
import os
import re
import shlex
import subprocess
from datetime import datetime, timezone, timedelta

import mysql.connector
from mysql.connector import Error as MySQLError

import command_classifier

IST = timezone(timedelta(hours=5, minutes=30))

# Fallback for colorful terminal output across Windows CMD and Linux
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except ImportError:
    class Fore:
        GREEN = RED = YELLOW = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = RESET_ALL = ""

# ---------------------------------------------------------------------
# CONFIG -- edit these to match your local MySQL instance.
# ---------------------------------------------------------------------
DB_HOST = "127.0.0.1"
DB_PORT = 3306
DB_USER = "root"
DB_PASSWORD = "aditya"   # <-- change this
DB_NAME = "brics"                    # <-- change if your schema is named differently

HOST = "127.0.0.1"
PORT = 9091  # internal-only; the firewall is the sole intended client

# ---------------------------------------------------------------------
# REAL SUBPROCESS EXECUTION: sandbox + allowlist + safety limits
# ---------------------------------------------------------------------
# Every real filesystem-touching command is confined under this
# directory. Anchored to this file's own location, not the process's
# cwd, for the same reason auth_db.py anchors its DB path this way.
SANDBOX_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_sandbox")

# Only these binaries ever reach a real subprocess.run(). Anything
# classified as EXECUTE that isn't in this set falls back to the
# existing mock_system_command() path -- never actually runs.
HARMLESS_COMMANDS = {"echo", "cat", "ls", "pwd", "whoami", "date", "wc"}

# 'cd' is not in HARMLESS_COMMANDS (it isn't a real subprocess -- it's a
# virtual, in-memory per-user cwd), but it still needs to be routed to
# real handling instead of falling through to the mock path.
VIRTUAL_COMMANDS = {"cd"}

# Explicit rejection of shell metacharacters, even though shell=False +
# shlex.split already prevents them from doing anything dangerous (they'd
# just be passed as literal argv text to the one binary being run, not
# interpreted). Rejecting them outright gives a clear error instead of
# confusing literal output, and is one more layer against relying on a
# single mechanism to prevent chaining.
FORBIDDEN_CHARS = re.compile(r'[;&|<>`$\n]')

COMMAND_TIMEOUT_SECONDS = 5


def _seed_sandbox():
    os.makedirs(SANDBOX_DIR, exist_ok=True)
    readme = os.path.join(SANDBOX_DIR, "README.txt")
    if not os.path.exists(readme):
        with open(readme, "w") as f:
            f.write(
                "SecureGateway backend sandbox.\n"
                "'cat', 'ls', 'wc' and 'cd' are confined to this directory tree for every "
                "authenticated user; nothing outside it is ever reachable.\n"
            )


def _resolve_sandbox_path(user_cwd: dict, user: str, raw_path: str):
    """Resolves raw_path to a real filesystem path and returns None if it
    would escape SANDBOX_DIR. A leading '/' is treated as sandbox-root
    (not the real host root) -- '/reports/q1.txt' means
    SANDBOX_DIR/reports/q1.txt, never a real host absolute path. Uses
    realpath so symlink-based escapes are caught too, not just '../'
    traversal."""
    sandbox_real = os.path.realpath(SANDBOX_DIR)
    raw_path = raw_path or "."
    if raw_path.startswith("/"):
        candidate = os.path.join(sandbox_real, raw_path.lstrip("/"))
    else:
        base = user_cwd.get(user, SANDBOX_DIR)
        candidate = os.path.join(base, raw_path)
    resolved = os.path.realpath(candidate)
    if resolved != sandbox_real and not resolved.startswith(sandbox_real + os.sep):
        return None
    return resolved


def _display_path(resolved: str) -> str:
    rel = os.path.relpath(resolved, os.path.realpath(SANDBOX_DIR))
    return "/" if rel == "." else f"/{rel}"


# ---------------------------------------------------------------------
# MOCKED SYSTEM COMMAND OUTPUT (never actually executed on this host)
# ---------------------------------------------------------------------
MOCK_RESPONSES = {
    "ls -la": "total 24\ndrwxr-xr-x  4 svc svc 4096 Sep 12 09:14 .\n-rw-r--r--  1 svc svc  220 Sep 12 09:14 app.py",
    "cat /var/log/syslog": "Sep 12 09:00:01 gw systemd[1]: Started Session.\nSep 12 09:01:12 gw kernel: [ready]",
    "git commit": "[main 4f2a1c3] update\n 1 file changed, 3 insertions(+)",
    "pip install": "Requirement already satisfied (simulated install, no packages were actually changed).",
    "systemctl status nginx": "* nginx.service - A high performance web server\n   Active: active (running)",
    "show status": "System Status: OPERATIONAL | Uptime: 4d 6h | Load: 0.32",
    "read patient_file.pdf": "[SIMULATED] File access logged. Preview: 'Patient record #4471 - routine checkup'",
    "python main.py": "[SIMULATED] main.py executed. Output: Service initialized successfully.",
    "view system_logs.txt": "[SIMULATED] 128 log lines displayed (info: 112, warning: 14, error: 2).",
}


def mock_system_command(cmd: str) -> str:
    key = cmd.strip().lower()
    for pattern, canned in MOCK_RESPONSES.items():
        if pattern in key:
            return canned
    return f"[SIMULATED] Command '{cmd}' executed successfully. (no real subprocess was run)"


def format_rows(columns, rows) -> str:
    if not rows:
        return "(0 rows returned)"
    str_rows = [[("" if v is None else str(v)) for v in row] for row in rows]
    widths = [
        max(len(str(col)), max((len(r[i]) for r in str_rows), default=0))
        for i, col in enumerate(columns)
    ]
    header = " | ".join(str(col).ljust(widths[i]) for i, col in enumerate(columns))
    sep = "-+-".join("-" * w for w in widths)
    lines = [header, sep]
    for r in str_rows:
        lines.append(" | ".join(r[i].ljust(widths[i]) for i in range(len(columns))))
    lines.append(f"({len(rows)} row(s) returned)")
    return "\n".join(lines)


class BackendServer:
    def __init__(self):
        self.db_conn = None
        self._connect_db()
        _seed_sandbox()
        self.user_cwd = {}  # {username: real absolute path, always inside SANDBOX_DIR}

    def _connect_db(self):
        try:
            self.db_conn = mysql.connector.connect(
                host=DB_HOST, port=DB_PORT, user=DB_USER,
                password=DB_PASSWORD, database=DB_NAME, autocommit=True
            )
            print(Fore.GREEN + f"[+] Connected to MySQL database '{DB_NAME}' at {DB_HOST}:{DB_PORT}")
        except MySQLError as e:
            self.db_conn = None
            print(Fore.RED + f"[!] MySQL connection failed: {e}")
            print(Fore.YELLOW + "[!] Server will keep running; SQL commands will error until the DB is reachable.")

    def _ensure_db(self):
        try:
            if self.db_conn is None or not self.db_conn.is_connected():
                self._connect_db()
        except Exception:
            self._connect_db()

    # -------------------------------------------------------------
    # SQL: READ and WRITE execute for real; DESTRUCT is hard-blocked
    # regardless of what permission the firewall granted upstream.
    # -------------------------------------------------------------
    def run_sql(self, command: str) -> str:
        cmd = command.strip().rstrip(";")

        # Redundant on purpose: handle_internal_command() already blocks
        # DESTRUCT-tier statements before this is ever called. A single
        # checkpoint guarding real DROP/DELETE/ALTER/TRUNCATE/CREATE/
        # GRANT/REVOKE/CALL access to a live database is not enough.
        if command_classifier.classify(cmd) == command_classifier.DESTRUCT:
            return (
                "[SERVER - REJECTED] Destructive/schema- or privilege-altering SQL is "
                "blocked by backend policy (redundant check)."
            )

        self._ensure_db()
        if self.db_conn is None:
            return "[SERVER ERROR] Database unavailable. Could not execute query."

        try:
            cursor = self.db_conn.cursor()
            cursor.execute(cmd)
            if cursor.with_rows:
                rows = cursor.fetchall()
                columns = [d[0] for d in cursor.description]
                result = format_rows(columns, rows)
            else:
                result = f"[OK] Statement executed. {cursor.rowcount} row(s) affected."
            cursor.close()
            return f"[SERVER - QUERY RESULT]\n{result}"
        except MySQLError as e:
            return f"[SERVER ERROR] SQL execution failed: {e}"

    # -------------------------------------------------------------
    # 'cd': virtual only. No real shell persists between requests --
    # each command arrives as a fresh, stateless payload -- so this
    # just tracks a per-user "current directory" in memory and applies
    # it as the cwd for that user's subsequent sandboxed commands.
    # -------------------------------------------------------------
    def _handle_cd(self, user: str, raw_path: str) -> str:
        raw_path = raw_path or "."
        resolved = _resolve_sandbox_path(self.user_cwd, user, raw_path)
        if resolved is None or not os.path.isdir(resolved):
            return f"[SERVER - REJECTED] Cannot cd into '{raw_path}': outside the sandbox or not a directory."
        self.user_cwd[user] = resolved
        return f"[OK] Changed directory to {_display_path(resolved)}"

    # -------------------------------------------------------------
    # Real subprocess execution for the harmless allowlist, sandboxed.
    # Everything else in the EXECUTE tier falls through to the mock.
    # -------------------------------------------------------------
    def run_system_command(self, command: str, user: str) -> str:
        if FORBIDDEN_CHARS.search(command):
            return "[SERVER - REJECTED] Pipelines, redirection, and command chaining are not permitted."

        try:
            argv = shlex.split(command)
        except ValueError as e:
            return f"[SERVER - REJECTED] Could not parse command: {e}"

        if not argv:
            return "[SERVER - REJECTED] Empty command."

        binary = argv[0].lower()
        args = argv[1:]

        if binary in VIRTUAL_COMMANDS:
            return self._handle_cd(user, args[0] if args else "")

        if binary not in HARMLESS_COMMANDS:
            # Not real-execution-eligible -- mocked, exactly as before.
            return mock_system_command(command)

        if binary == "pwd":
            return _display_path(self.user_cwd.get(user, SANDBOX_DIR))

        if binary in ("cat", "wc"):
            if not args:
                return f"[SERVER - REJECTED] '{binary}' requires at least one file argument."
            argv_real = [binary]
            saw_file_arg = False
            cwd_now = self.user_cwd.get(user, SANDBOX_DIR)
            for raw in args:
                if raw.startswith("-"):
                    argv_real.append(raw)  # pass flags (-l, -n, ...) through unresolved
                    continue
                resolved = _resolve_sandbox_path(self.user_cwd, user, raw)
                if resolved is None or not os.path.isfile(resolved):
                    return f"[SERVER - REJECTED] '{raw}' is outside the sandbox or does not exist."
                # Pass a cwd-relative path to the real subprocess (not the
                # resolved absolute host path) so tools like 'wc', which
                # echo their filename argument in their own output, don't
                # leak the real host directory structure to the client.
                argv_real.append(os.path.relpath(resolved, cwd_now))
                saw_file_arg = True
            if not saw_file_arg:
                return f"[SERVER - REJECTED] '{binary}' requires at least one file argument."

        elif binary == "ls":
            flags = [a for a in args if a.startswith("-")]
            targets = [a for a in args if not a.startswith("-")]
            target = targets[0] if targets else "."
            resolved = _resolve_sandbox_path(self.user_cwd, user, target)
            if resolved is None or not os.path.isdir(resolved):
                return f"[SERVER - REJECTED] '{target}' is outside the sandbox or is not a directory."
            argv_real = [binary] + flags + [resolved]

        else:  # echo, whoami, date -- no filesystem paths to confine
            argv_real = [binary] + args

        try:
            result = subprocess.run(
                argv_real, shell=False, capture_output=True, text=True,
                timeout=COMMAND_TIMEOUT_SECONDS,
                cwd=self.user_cwd.get(user, SANDBOX_DIR),
            )
        except subprocess.TimeoutExpired:
            return f"[SERVER ERROR] Command '{binary}' timed out after {COMMAND_TIMEOUT_SECONDS}s."
        except FileNotFoundError:
            return f"[SERVER ERROR] '{binary}' is not available on this host."
        except Exception as e:
            return f"[SERVER ERROR] Failed to execute '{binary}': {e}"

        output = (result.stdout or "") + (result.stderr or "")
        return output.strip() or "[OK] Command executed with no output."

    # -------------------------------------------------------------
    # Double safety net: independently re-classify the raw command
    # with the same shared command_classifier the firewall used, and
    # refuse to run anything if the two disagree.
    # -------------------------------------------------------------
    def handle_internal_command(self, command: str, declared_category, user: str) -> str:
        if declared_category is None:
            return ("[SERVER - REJECTED] Missing permission classification from the gateway; "
                    "refusing to execute.")

        local_category = command_classifier.classify(command)

        if local_category != declared_category:
            return (
                "[SERVER - REJECTED] Permission-tier mismatch between gateway and backend "
                f"classification (gateway declared '{declared_category}', backend "
                f"independently computed '{local_category}'). Refusing to execute -- "
                "treating this as a possible tampering or backdoor attempt, not just a bug."
            )

        if local_category == command_classifier.DESTRUCT:
            return (
                "[SERVER - REJECTED] Destructive/schema- or privilege-altering SQL is "
                "blocked by backend policy regardless of firewall-level 'D' permission. "
                "This is an intentional second safety net independent of the gateway."
            )

        if command_classifier.is_sql(command):
            return self.run_sql(command)

        return self.run_system_command(command, user)

    def handle_request(self, payload: dict) -> str:
        channel = payload.get("channel", "WEB")
        command = (payload.get("command") or "").strip()
        user = payload.get("user", "unknown")
        source_ip = payload.get("source_ip", "unknown")
        status = payload.get("status", "")
        category = payload.get("category")  # RWXD tier the firewall already gated on
        ts = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")

        if channel == "WEB" and not command:
            print(Fore.CYAN + f"[{ts}] WEB visit from {source_ip}")
            return "<html><body><h1>SecureGateway Backend: Service Operational</h1></body></html>"

        tag = "SQL" if command_classifier.is_sql(command) else "SYSTEM"
        warn = f" [{status}]" if status == "ORANGE" else ""
        print(Fore.CYAN + f"[{ts}] {tag} request{warn} | user={user} ip={source_ip} | {command!r}")

        if channel == "INTERNAL":
            # Only authenticated, firewall-vetted traffic can ever reach
            # real SQL writes or real subprocess execution.
            return self.handle_internal_command(command, category, user)

        # WEB channel with a command (anonymous, unauthenticated visitor)
        # -- always mocked, never real execution or real SQL, regardless
        # of what the command looks like.
        return mock_system_command(command)

    async def handle_connection(self, reader, writer):
        peer = writer.get_extra_info('peername')
        peer_ip = peer[0] if peer else "unknown"

        # Defense-in-depth: this backend should only ever be reached by the
        # firewall/gateway process running on the same machine.
        if peer_ip not in ("127.0.0.1", "::1"):
            writer.close()
            await writer.wait_closed()
            return

        try:
            data = await reader.read(65536)
            if not data:
                return
            try:
                payload = json.loads(data.decode('utf-8', errors='ignore').strip())
            except json.JSONDecodeError:
                payload = {"channel": "WEB", "command": "", "source_ip": peer_ip}

            result = self.handle_request(payload)
            writer.write(result.encode('utf-8'))
            await writer.drain()
        except Exception as e:
            try:
                writer.write(f"[SERVER ERROR] {e}".encode('utf-8'))
                await writer.drain()
            except Exception:
                pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        server = await asyncio.start_server(self.handle_connection, HOST, PORT)
        print(Fore.GREEN + Style.BRIGHT + "=" * 70)
        print(Fore.GREEN + Style.BRIGHT + "   SECUREGATEWAY BACKEND APPLICATION SERVER (internal, gateway-only)")
        print(Fore.GREEN + Style.BRIGHT + "=" * 70 + Style.RESET_ALL)
        print(f"Listening on: {Fore.YELLOW}{HOST}:{PORT}{Style.RESET_ALL} "
              f"(accepts firewall-forwarded traffic only)")
        print(f"Sandbox directory: {Fore.YELLOW}{SANDBOX_DIR}{Style.RESET_ALL}\n")
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    backend = BackendServer()
    try:
        asyncio.run(backend.start())
    except KeyboardInterrupt:
        print("\n" + Fore.RED + "[-] Backend server clean exit.")
