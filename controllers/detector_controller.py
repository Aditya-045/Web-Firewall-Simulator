"""
detector_controller.py -- starts/stops the Malicious Content Detector.
=========================================================================
Manages the detector's two processes from the WAF Simulator GUI:

    backend   python -m uvicorn app.main:app      (FastAPI, port 8000)
    frontend  npm run dev                          (Vite,    port 5173)

This module is deliberately independent of the simulator's own process
controllers (backend_controllers.py) and of SimulatorConfig: it imports only
QtCore/QtNetwork, takes the simulator's directory as its one constructor
argument, and talks to the rest of the app purely through signals. That keeps
the integration to a few lines in main.py and makes it testable headless.

Startup sequence (each step gated on the previous one actually succeeding):
    1. pre-flight checks, all reported together in ONE message
    2. `npm install` if frontend/node_modules is missing
    3. start uvicorn, poll GET /health until it answers
    4. start `npm run dev`, poll the Vite URL until it answers
    5. emit ready(url) -> main.py opens the browser

Why the ports are fixed (8000 / 5173) and never auto-shifted: the frontend's
vite.config.js proxies /api to 127.0.0.1:8000 and the backend's CORS list
only allows localhost:5173. If either port is taken the user is told which
one, and Vite is started with --strictPort so it fails loudly instead of
silently drifting to 5174.

Stopping kills the whole process TREE, not just the direct child. This is the
important part on Windows: `npm run dev` is npm.cmd -> cmd.exe -> node ->
vite, and terminating only the top process leaves vite running and holding
port 5173 after the simulator closes. Windows uses `taskkill /T /F`; other
platforms use psutil if it is installed (best-effort -- the target platform
of this integration is Windows).
"""
from __future__ import annotations

import importlib.util
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from collections import deque
from pathlib import Path

from PySide6.QtCore import QObject, QProcess, QProcessEnvironment, QTimer, QUrl, Signal
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkProxy, QNetworkReply, QNetworkRequest

# ---------------------------------------------------------------------------
# Configuration -- the only things you should ever need to edit.
# ---------------------------------------------------------------------------
# Folder (inside the simulator's directory) that holds the detector. Leave as
# None to auto-discover: any sub-folder containing both backend/app/main.py
# and frontend/package.json is accepted. Set a name (or an absolute path) to
# pin it explicitly, e.g. "malicious_content_detector".
DETECTOR_FOLDER_NAME: str | None = None

BACKEND_HOST = "127.0.0.1"
BACKEND_PORT = 8000
FRONTEND_HOST = "127.0.0.1"
FRONTEND_PORT = 5173

BACKEND_READY_TIMEOUT_S = 120   # first import of scikit-learn etc. can be slow on Windows
FRONTEND_READY_TIMEOUT_S = 90
POLL_INTERVAL_MS = 700
LOG_BUFFER_LINES = 3000
KILL_WAIT_MS = 3000

# State names (also what state_changed emits).
STOPPED = "stopped"
INSTALLING = "installing"
STARTING_BACKEND = "starting_backend"
STARTING_FRONTEND = "starting_frontend"
RUNNING = "running"

# Imported by the backend at runtime -> (module, pip name). `whois` is
# optional in the backend (it degrades gracefully), so it is not required here.
REQUIRED_MODULES = (
    ("uvicorn", "uvicorn"), ("fastapi", "fastapi"), ("sqlalchemy", "sqlalchemy"),
    ("pydantic", "pydantic"), ("joblib", "joblib"), ("numpy", "numpy"),
    ("sklearn", "scikit-learn"), ("tldextract", "tldextract"),
    ("requests", "requests"), ("dns", "dnspython"),
)
REQUIRED_MODELS = ("url_model.joblib", "text_model.joblib")

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_CREATE_NO_WINDOW = 0x08000000


# ---------------------------------------------------------------------------
# Helpers (module level so they can be unit-tested)
# ---------------------------------------------------------------------------
def port_in_use(host: str, port: int) -> bool:
    """True only if something ACCEPTS a connection. Any failure/timeout counts
    as 'free' -- a live listener on loopback accepts immediately."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.4)
    try:
        return s.connect_ex((host, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def looks_like_detector(path: Path) -> bool:
    return (path / "backend" / "app" / "main.py").is_file() and \
           (path / "frontend" / "package.json").is_file()


def kill_process_tree(pid: int) -> None:
    """Kill `pid` and every descendant. Never raises."""
    if pid <= 0:
        return
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True, timeout=10,
                           creationflags=_CREATE_NO_WINDOW)
            return
        try:
            import psutil
        except ImportError:
            return  # caller falls back to QProcess.kill() on the direct child
        try:
            parent = psutil.Process(pid)
        except psutil.NoSuchProcess:
            return
        victims = parent.children(recursive=True) + [parent]
        for p in victims:
            try:
                p.kill()
            except psutil.NoSuchProcess:
                pass
        psutil.wait_procs(victims, timeout=3)
    except Exception:
        pass


class DetectorController(QObject):
    state_changed = Signal(str)   # one of the state constants above
    log_line = Signal(str)        # every log line, already timestamped
    ready = Signal(str)           # frontend URL, once BOTH servers answer
    failed = Signal(str, str)     # (title, details) -- show to the user

    def __init__(self, app_dir, parent=None):
        super().__init__(parent)
        self._app_dir = Path(app_dir)
        self._state = STOPPED
        self._detector_dir: Path | None = None
        self._npm: str | None = None
        self._procs: dict[str, QProcess] = {}
        self._partial: dict[str, str] = {}
        self._lines: deque[str] = deque(maxlen=LOG_BUFFER_LINES)
        self._logfile = None
        self._log_path: Path | None = None

        self._nam = QNetworkAccessManager(self)
        self._nam.setProxy(QNetworkProxy(QNetworkProxy.NoProxy))  # never route loopback via a system proxy
        self._poll = QTimer(self)
        self._poll.setInterval(POLL_INTERVAL_MS)
        self._poll.timeout.connect(self._on_poll)
        self._poll_target: str | None = None
        self._poll_url = ""
        self._poll_deadline = 0.0
        self._probe_inflight = False

    # ------------------------------------------------------------ queries
    def state(self) -> str:
        return self._state

    def is_idle(self) -> bool:
        return self._state == STOPPED

    def is_running(self) -> bool:
        return self._state == RUNNING

    def frontend_url(self) -> str:
        return f"http://{FRONTEND_HOST}:{FRONTEND_PORT}/"

    def log_path(self) -> Path | None:
        return self._log_path

    def log_lines(self) -> list[str]:
        return list(self._lines)

    def status_word(self) -> str:
        return {STOPPED: "offline", INSTALLING: "installing deps",
                STARTING_BACKEND: "starting", STARTING_FRONTEND: "starting",
                RUNNING: "running"}.get(self._state, self._state)

    # ----------------------------------------------------------- logging
    def _log(self, line: str) -> None:
        stamped = f"{time.strftime('%H:%M:%S')} {line}"
        self._lines.append(stamped)
        if self._logfile:
            try:
                self._logfile.write(stamped + "\n")
                self._logfile.flush()
            except (OSError, ValueError):
                self._logfile = None
        self.log_line.emit(stamped)

    def _open_log(self) -> None:
        self._close_log()
        for base in (self._app_dir / "logs", Path(tempfile.gettempdir())):
            try:
                base.mkdir(parents=True, exist_ok=True)
                self._log_path = base / "malicious_detector.log"
                self._logfile = open(self._log_path, "w", encoding="utf-8")  # truncated each run
                return
            except OSError:
                continue
        self._log_path = None

    def _close_log(self) -> None:
        if self._logfile:
            try:
                self._logfile.close()
            except OSError:
                pass
        self._logfile = None

    def _tail(self, n: int = 25) -> str:
        return "\n".join(list(self._lines)[-n:])

    def _set_state(self, state: str) -> None:
        if state != self._state:
            self._state = state
            self.state_changed.emit(state)

    # --------------------------------------------------------- pre-flight
    def _find_detector_dir(self) -> Path | None:
        if DETECTOR_FOLDER_NAME:
            p = Path(DETECTOR_FOLDER_NAME)
            p = p if p.is_absolute() else self._app_dir / p
            return p if looks_like_detector(p) else None
        try:
            matches = [c for c in sorted(self._app_dir.iterdir())
                       if c.is_dir() and looks_like_detector(c)]
        except OSError:
            return None
        if not matches:
            return None
        preferred = [m for m in matches if any(k in m.name.lower() for k in ("malicious", "detector", "threat"))]
        chosen = (preferred or matches)[0]
        if len(matches) > 1:
            self._log(f"[detector] note: {len(matches)} candidate folders found, using '{chosen.name}'. "
                      f"Set DETECTOR_FOLDER_NAME in detector_controller.py to choose explicitly.")
        return chosen

    def _preflight(self) -> list[str]:
        problems: list[str] = []

        if getattr(sys, "frozen", False):
            problems.append("The simulator is running as a frozen executable, so sys.executable is not a "
                            "Python interpreter and the backend cannot be launched with it.")
        if sys.version_info < (3, 10):
            problems.append(f"The backend needs Python 3.10 or newer; the simulator is running "
                            f"{sys.version.split()[0]} ({sys.executable}).")

        self._detector_dir = self._find_detector_dir()
        d = self._detector_dir
        if d is None:
            where = f"'{DETECTOR_FOLDER_NAME}'" if DETECTOR_FOLDER_NAME else f"inside {self._app_dir}"
            problems.append(
                f"The Malicious Content Detector folder was not found {where}.\n"
                "Expected a folder containing:\n"
                "    backend/app/main.py\n"
                "    frontend/package.json")
        else:
            for name in REQUIRED_MODELS:
                if not (d / "backend" / "app" / "models" / name).is_file():
                    problems.append(
                        f"Trained model file missing: backend/app/models/{name}\n"
                        "The backend refuses to start without it. Train it with the scripts in "
                        "backend/scripts (e.g. on Colab) and copy the .joblib file there.")

        missing = [pip for mod, pip in REQUIRED_MODULES if importlib.util.find_spec(mod) is None]
        if missing:
            req = f'{d / "backend" / "requirements.txt"}' if d else "backend/requirements.txt"
            problems.append(
                f"These Python packages are missing from the simulator's interpreter "
                f"({sys.executable}): {', '.join(missing)}\n"
                f'Install them with:\n    "{sys.executable}" -m pip install -r "{req}"')

        self._npm = shutil.which("npm")
        if self._npm is None:
            problems.append("npm was not found on PATH. Install Node.js (LTS) and restart the simulator "
                            "so it picks up the updated PATH.")

        for label, host, port in (("backend", BACKEND_HOST, BACKEND_PORT),
                                  ("frontend", FRONTEND_HOST, FRONTEND_PORT)):
            if port_in_use(host, port):
                problems.append(
                    f"Port {port} ({label}) is already in use. If the detector is already running "
                    f"(for example started by hand), stop it first; otherwise close whatever is using the port. "
                    f"The ports are fixed because the frontend proxy and backend CORS settings depend on them.")
        return problems

    # -------------------------------------------------------------- start
    def start(self) -> None:
        if not self.is_idle():
            return
        self._lines.clear()
        self._open_log()
        self._log("[detector] starting Malicious Content Detector")
        problems = self._preflight()
        if problems:
            for p in problems:
                self._log("[detector] PRE-FLIGHT: " + p.replace("\n", " | "))
            self._close_log()
            self.failed.emit("Cannot start the Malicious Content Detector",
                             "\n\n".join(f"{i}. {p}" for i, p in enumerate(problems, 1)))
            return

        self._log(f"[detector] folder: {self._detector_dir}")
        self._log(f"[detector] python: {sys.executable}")
        self._log(f"[detector] npm:    {self._npm}")
        if (self._detector_dir / "frontend" / "node_modules").is_dir():
            self._begin_backend()
        else:
            self._begin_install()

    def _env(self) -> QProcessEnvironment:
        env = QProcessEnvironment.systemEnvironment()
        env.insert("PYTHONUNBUFFERED", "1")
        env.insert("PYTHONIOENCODING", "utf-8")
        env.insert("NO_COLOR", "1")
        env.insert("FORCE_COLOR", "0")
        return env

    def _spawn(self, tag: str, program: str, args: list[str], cwd: Path) -> bool:
        proc = QProcess(self)
        proc.setWorkingDirectory(str(cwd))
        proc.setProcessEnvironment(self._env())
        proc.setProcessChannelMode(QProcess.MergedChannels)
        proc.readyReadStandardOutput.connect(lambda p=proc, t=tag: self._drain(p, t))
        proc.finished.connect(lambda code, status, t=tag: self._on_finished(t, code, status))
        proc.errorOccurred.connect(lambda err, t=tag: self._on_proc_error(t, err))
        self._procs[tag] = proc
        self._partial[tag] = ""
        self._log(f"[detector] launching {tag}: {program} {' '.join(args)}   (cwd: {cwd})")
        proc.start(program, args)
        return True

    def _begin_install(self) -> None:
        self._set_state(INSTALLING)
        self._log("[detector] frontend/node_modules not found -- running 'npm install' "
                  "(first run only; this can take a few minutes)")
        self._spawn("npm install", self._npm, ["install", "--no-audit", "--no-fund"],
                    self._detector_dir / "frontend")

    def _begin_backend(self) -> None:
        self._set_state(STARTING_BACKEND)
        self._spawn("backend", sys.executable,
                    ["-m", "uvicorn", "app.main:app", "--host", BACKEND_HOST, "--port", str(BACKEND_PORT)],
                    self._detector_dir / "backend")
        self._start_poll("backend", f"http://{BACKEND_HOST}:{BACKEND_PORT}/health", BACKEND_READY_TIMEOUT_S)

    def _begin_frontend(self) -> None:
        self._set_state(STARTING_FRONTEND)
        self._spawn("frontend", self._npm,
                    ["run", "dev", "--", "--host", FRONTEND_HOST, "--port", str(FRONTEND_PORT), "--strictPort"],
                    self._detector_dir / "frontend")
        self._start_poll("frontend", self.frontend_url(), FRONTEND_READY_TIMEOUT_S)

    # ------------------------------------------------- readiness polling
    def _start_poll(self, target: str, url: str, timeout_s: int) -> None:
        self._poll_target = target
        self._poll_url = url
        self._poll_deadline = time.monotonic() + timeout_s
        self._probe_inflight = False
        self._poll.start()

    def _stop_poll(self) -> None:
        self._poll.stop()
        self._poll_target = None

    def _on_poll(self) -> None:
        if self._poll_target is None:
            return
        if time.monotonic() > self._poll_deadline:
            target = self._poll_target
            self._fail(f"The {target} did not become ready",
                       f"No response from {self._poll_url} within the time limit. "
                       f"See the log output below.")
            return
        if self._probe_inflight:
            return
        self._probe_inflight = True
        req = QNetworkRequest(QUrl(self._poll_url))
        req.setTransferTimeout(1500)
        reply = self._nam.get(req)
        reply.finished.connect(lambda r=reply, t=self._poll_target: self._on_probe(r, t))

    def _on_probe(self, reply: QNetworkReply, target: str) -> None:
        self._probe_inflight = False
        ok = reply.error() == QNetworkReply.NoError
        reply.deleteLater()
        if not ok or target != self._poll_target:
            return  # not up yet (or stale reply from an earlier step)
        self._stop_poll()
        if target == "backend":
            self._log(f"[detector] backend is healthy ({self._poll_url})")
            self._begin_frontend()
        else:
            self._set_state(RUNNING)
            self._log(f"[detector] RUNNING -- UI {self.frontend_url()}  |  API http://{BACKEND_HOST}:{BACKEND_PORT}/docs")
            self.ready.emit(self.frontend_url())

    # ------------------------------------------------- process plumbing
    def _drain(self, proc: QProcess, tag: str) -> None:
        data = bytes(proc.readAllStandardOutput()).decode("utf-8", "replace")
        if not data:
            return
        text = self._partial.get(tag, "") + data.replace("\r\n", "\n").replace("\r", "\n")
        parts = text.split("\n")
        self._partial[tag] = parts.pop()
        for line in parts:
            line = _ANSI_RE.sub("", line).rstrip()
            if line:
                self._log(f"[{tag}] {line}")

    def _flush_partial(self, tag: str) -> None:
        rest = _ANSI_RE.sub("", self._partial.pop(tag, "")).rstrip()
        if rest:
            self._log(f"[{tag}] {rest}")

    def _on_finished(self, tag: str, code: int, status) -> None:
        proc = self._procs.get(tag)
        if proc is not None:
            self._drain(proc, tag)
        self._flush_partial(tag)
        crashed = status == QProcess.CrashExit
        self._log(f"[detector] {tag} exited (code {code}{', crashed' if crashed else ''})")

        if tag == "npm install":
            self._procs.pop(tag, None)
            if code == 0 and not crashed:
                self._begin_backend()
            else:
                self._fail("npm install failed",
                           "The frontend's dependencies could not be installed. Check your network "
                           "connection / npm registry access.")
            return
        self._fail(f"The {tag} stopped unexpectedly", f"It exited with code {code}.")

    def _on_proc_error(self, tag: str, err) -> None:
        if err == QProcess.FailedToStart:
            self._fail(f"Could not launch the {tag}",
                       "The operating system refused to start the process (see the log for the exact command).")
        # Crashed / read-write errors are followed by finished(), handled there.

    # ------------------------------------------------- failure / stop
    def _fail(self, title: str, detail: str) -> None:
        if self.is_idle():
            return
        tail = self._tail()
        self._log(f"[detector] FAILED: {title}")
        self._teardown()
        self._set_state(STOPPED)
        self._close_log()
        self.failed.emit(title, f"{detail}\n\nLast log lines:\n{tail}")

    def _teardown(self) -> None:
        self._stop_poll()
        # Frontend first, then backend, so the UI never outlives the API it proxies to.
        for tag in ("frontend", "backend", "npm install"):
            proc = self._procs.pop(tag, None)
            if proc is None:
                continue
            try:
                self._drain(proc, tag)
                self._flush_partial(tag)
                proc.blockSignals(True)            # we are killing it on purpose; no crash reports
                if proc.state() != QProcess.NotRunning:
                    kill_process_tree(int(proc.processId()))
                    if proc.state() != QProcess.NotRunning:
                        proc.kill()                # fallback if tree-kill was unavailable
                    proc.waitForFinished(KILL_WAIT_MS)
            finally:
                proc.deleteLater()
        self._partial.clear()

    def stop(self, wait: bool = True) -> None:
        """Stop everything. Synchronous: when it returns, both processes (and
        their children) are gone. `wait` is accepted for symmetry with the
        simulator's other controllers."""
        if self.is_idle():
            return
        self._log("[detector] stopping")
        self._teardown()
        self._set_state(STOPPED)
        self._log("[detector] stopped")
        self._close_log()
