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
    REPLACE) SQL for real against a database (tables: gdp_data,
    brics_debt_trade). By default this is a real MySQL instance, exactly
    as before; pass --db-engine mock (or set SG_DB_ENGINE=mock) to use a
    disposable, sandboxed SQLite stand-in instead (see mock_mysql.py) --
    this is what the PySide6 GUI simulator uses by default so it never
    touches a real MySQL install on the operator's machine.
  - Refuse DESTRUCT-tier SQL (DROP/DELETE/ALTER/TRUNCATE/CREATE/GRANT/
    REVOKE/CALL) unconditionally, regardless of firewall-level 'D'
    permission, and regardless of which storage engine is in use. This is
    a deliberate, hardcoded second safety net.
  - Execute a small allowlist of harmless shell commands for real
    (echo, cat, ls, pwd, whoami, date, wc), each confined to a sandbox
    directory.
  - Return realistic *simulated* output for every other system-style
    command -- nothing is actually executed for those.
  - Independently re-classify every INTERNAL command with the same
    shared command_classifier the firewall used, and refuse to run
    anything if its own classification disagrees.

CHANGES FROM THE ORIGINAL (for the PySide6 GUI simulator, Prototype 1):
  - All previously-hardcoded DB_HOST/DB_PORT/DB_USER/DB_PASSWORD/DB_NAME
    and the server's own HOST/PORT are now read from command-line
    arguments (or SG_* environment variables), falling back to the exact
    same hardcoded values as before if nothing is supplied -- so running
    `python server.py` with no arguments behaves identically to the
    original file.
  - A new --db-engine {mysql,mock} flag (default: mysql, unchanged
    behavior) selects the storage engine. The GUI always launches this
    script with --db-engine mock unless the operator explicitly opts
    into Real MySQL Mode in the Server Configuration dialog.
  - --working-dir controls where the mock engine's disposable SQLite file
    is created; it is never written anywhere else on the host.

Run this BEFORE starting aegis_firewall.py, in its own terminal:
    python server.py
"""

import argparse
import asyncio
import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone, timedelta

import mysql.connector
from mysql.connector import Error as MySQLError

import command_classifier

try:
    import mock_mysql
except ImportError:
    mock_mysql = None  # only required when --db-engine mock is actually selected

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
# CONFIG -- overridable via CLI args / SG_* environment variables.
# Every default below is exactly the original hardcoded value, so
# `python server.py` with no arguments is unchanged from before.
# ---------------------------------------------------------------------
def _env_default(name: str, fallback):
    return os.environ.get(name, fallback)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="SecureGateway backend application server.")
    parser.add_argument("--host", default=_env_default("SG_BACKEND_HOST", "127.0.0.1"),
                         help="Backend listen host (default: 127.0.0.1, internal-only).")
    parser.add_argument("--port", type=int, default=int(_env_default("SG_BACKEND_PORT", "9091")),
                         help="Backend listen port (default: 9091).")
    parser.add_argument("--db-engine", choices=("mysql", "mock"),
                         default=_env_default("SG_DB_ENGINE", "mysql"),
                         help="'mysql' (default, original behavior) connects to a real MySQL "
                              "server. 'mock' uses a disposable, sandboxed SQLite file instead "
                              "and never touches a real MySQL install. The GUI simulator passes "
                              "--db-engine mock by default.")
    parser.add_argument("--working-dir", default=_env_default("SG_WORKING_DIR", os.path.dirname(os.path.abspath(__file__))),
                         help="Directory the mock engine's disposable SQLite file is created in. "
                              "Ignored when --db-engine mysql.")
    parser.add_argument("--mysql-host", default=_env_default("SG_MYSQL_HOST", "127.0.0.1"))
    parser.add_argument("--mysql-port", type=int, default=int(_env_default("SG_MYSQL_PORT", "3306")))
    parser.add_argument("--mysql-user", default=_env_default("SG_MYSQL_USER", "root"))
    parser.add_argument("--mysql-password", default=_env_default("SG_MYSQL_PASSWORD", "aditya"))
    parser.add_argument("--mysql-database", default=_env_default("SG_MYSQL_DATABASE", "brics"))
    return parser.parse_args(argv)


ARGS = parse_args()

DB_ENGINE = ARGS.db_engine
DB_HOST = ARGS.mysql_host
DB_PORT = ARGS.mysql_port
DB_USER = ARGS.mysql_user
DB_PASSWORD = ARGS.mysql_password
DB_NAME = ARGS.mysql_database
WORKING_DIR = ARGS.working_dir

HOST = ARGS.host
PORT = ARGS.port  # internal-only; the firewall is the sole intended client

# ---------------------------------------------------------------------
# REAL SUBPROCESS EXECUTION: sandbox + allowlist + safety limits
# ---------------------------------------------------------------------
SANDBOX_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_sandbox")
HARMLESS_COMMANDS = {"echo", "cat", "ls", "pwd", "whoami", "date", "wc"}
VIRTUAL_COMMANDS = {"cd"}
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
        self.user_cwd = {}

    # -------------------------------------------------------------
    # DB connection: real MySQL (unchanged) or the sandboxed mock
    # engine, selected once at startup by --db-engine / SG_DB_ENGINE.
    # -------------------------------------------------------------
    def _connect_db(self):
        if DB_ENGINE == "mock":
            if mock_mysql is None:
                self.db_conn = None
                print(Fore.RED + "[!] --db-engine mock was requested but mock_mysql.py could not be imported.")
                return
            try:
                self.db_conn = mock_mysql.connect(WORKING_DIR)
                print(Fore.GREEN + f"[+] Using sandboxed MOCK database at "
                                    f"{os.path.join(WORKING_DIR, mock_mysql.DB_FILENAME)}")
                print(Fore.YELLOW + "[i] No real MySQL server is used or required in this mode; "
                                     "nothing on this machine outside the working directory is touched.")
            except Exception as e:
                self.db_conn = None
                print(Fore.RED + f"[!] Could not initialize mock database: {e}")
            return

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
    # regardless of engine or what permission the firewall granted.
    # -------------------------------------------------------------
    def run_sql(self, command: str) -> str:
        cmd = command.strip().rstrip(";")

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
            if DB_ENGINE == "mock":
                self.db_conn.commit()
            return f"[SERVER - QUERY RESULT]\n{result}"
        except (MySQLError, Exception) as e:
            return f"[SERVER ERROR] SQL execution failed: {e}"

    def _handle_cd(self, user: str, raw_path: str) -> str:
        raw_path = raw_path or "."
        resolved = _resolve_sandbox_path(self.user_cwd, user, raw_path)
        if resolved is None or not os.path.isdir(resolved):
            return f"[SERVER - REJECTED] Cannot cd into '{raw_path}': outside the sandbox or not a directory."
        self.user_cwd[user] = resolved
        return f"[OK] Changed directory to {_display_path(resolved)}"

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
                    argv_real.append(raw)
                    continue
                resolved = _resolve_sandbox_path(self.user_cwd, user, raw)
                if resolved is None or not os.path.isfile(resolved):
                    return f"[SERVER - REJECTED] '{raw}' is outside the sandbox or does not exist."
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

        else:
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
        category = payload.get("category")
        ts = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")

        if channel == "WEB" and not command:
            print(Fore.CYAN + f"[{ts}] WEB visit from {source_ip}")
            return "<html><body><h1>SecureGateway Backend: Service Operational</h1></body></html>"

        tag = "SQL" if command_classifier.is_sql(command) else "SYSTEM"
        warn = f" [{status}]" if status == "ORANGE" else ""
        print(Fore.CYAN + f"[{ts}] {tag} request{warn} | user={user} ip={source_ip} | {command!r}")

        if channel == "INTERNAL":
            return self.handle_internal_command(command, category, user)

        return mock_system_command(command)

    async def handle_connection(self, reader, writer):
        peer = writer.get_extra_info('peername')
        peer_ip = peer[0] if peer else "unknown"

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
        print(f"DB engine: {Fore.YELLOW}{DB_ENGINE}{Style.RESET_ALL}")
        print(f"Sandbox directory: {Fore.YELLOW}{SANDBOX_DIR}{Style.RESET_ALL}\n")
        async with server:
            await server.serve_forever()


if __name__ == "__main__":
    backend = BackendServer()
    try:
        asyncio.run(backend.start())
    except KeyboardInterrupt:
        print("\n" + Fore.RED + "[-] Backend server clean exit.")
