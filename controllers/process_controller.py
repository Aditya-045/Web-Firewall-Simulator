"""
process_controller.py -- QProcess wrapper shared by all four backend
processes (firewall, backend server, client, admin console).

Design principle (per the SRS): the existing CLI programs are launched
completely unmodified (server.py aside, whose only change is the
argv-driven DB engine switch), as subprocesses. This class never parses
or rewrites their output for logic purposes -- it only republishes raw
lines to the GUI via a Qt signal so terminal widgets can display them.
No socket, MySQL, or subprocess-launch call ever happens on the GUI
thread: QProcess itself is asynchronous/non-blocking by design.
"""

from __future__ import annotations

import codecs
import sys
from typing import Optional

from PySide6.QtCore import QObject, QProcess, QTimer, Signal


class ProcessController(QObject):
    """Wraps one long-lived child process (python <script> [args...])."""

    output_text = Signal(str)          # raw decoded chunk, NOT line-buffered --
                                        # interactive CLIs (client.py, admin_console.py)
                                        # print prompts like "Select test> " via input()
                                        # with no trailing newline, and those must still
                                        # reach the terminal widget immediately.
    state_changed = Signal(str)        # "stopped" | "starting" | "running" | "ready" | "crashed"
    error_occurred = Signal(str)

    def __init__(self, label: str, parent: Optional[QObject] = None):
        super().__init__(parent)
        self.label = label
        self._proc = QProcess(self)
        self._proc.setProcessChannelMode(QProcess.MergedChannels)
        self._proc.readyReadStandardOutput.connect(self._on_ready_read)
        self._proc.started.connect(lambda: self.state_changed.emit("running"))
        self._proc.errorOccurred.connect(self._on_error)
        self._proc.finished.connect(self._on_finished)
        # Incremental UTF-8 decoder: a raw byte chunk from QProcess can end
        # mid-multibyte-character; this keeps that trailing partial byte
        # sequence and prepends it to the next chunk instead of corrupting
        # or dropping it.
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._ready_marker: Optional[str] = None
        self._seen_ready = False
        self._stop_requested = False
        self._generation = 0   # bumped on every start(); stale kill timers check it

    @property
    def awaits_ready(self) -> bool:
        """True if this process has a ready_marker, i.e. 'running' alone
        does not yet mean it is usable."""
        return self._ready_marker is not None

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------
    def start(self, script_path: str, args: list[str], working_dir: str, env: Optional[dict] = None,
              ready_marker: Optional[str] = None):
        """ready_marker: if given, is_ready()/state "ready" is only reached
        once this substring is seen in the child's output -- because a
        QProcess reaching "running" only means the OS process launched, not
        that an asyncio server inside it has actually bound its socket yet.
        Actions that depend on the firewall/backend truly being reachable
        (Connect Client, Open Admin Terminal) should gate on is_ready(),
        not is_running()."""
        if self.is_running():
            return
        if env is not None:
            from PySide6.QtCore import QProcessEnvironment
            qenv = QProcessEnvironment.systemEnvironment()
            for k, v in env.items():
                qenv.insert(k, str(v))
            self._proc.setProcessEnvironment(qenv)
        self._ready_marker = ready_marker
        self._seen_ready = False
        self._stop_requested = False
        self._generation += 1
        self._proc.setWorkingDirectory(working_dir)
        self.state_changed.emit("starting")
        self._proc.start(sys.executable, [script_path, *args])

    def stop(self, graceful_timeout_ms: int = 2000, wait: bool = False):
        """Stops the child without blocking the GUI thread (unless wait=True,
        used only while the application is closing).

        Windows: QProcess.terminate() only posts WM_CLOSE, which console
        programs such as these never receive, so a graceful attempt would
        just freeze for the whole timeout -- kill() is used directly (the
        backend keeps no state that needs a clean shutdown: the dossier is
        rewritten on every entry, SQLite commits per statement).
        Elsewhere: terminate(), then kill() after graceful_timeout_ms if
        it is still alive."""
        if not self.is_running():
            return
        self._stop_requested = True
        if sys.platform == "win32":
            self._proc.kill()
        else:
            self._proc.terminate()
            gen = self._generation
            QTimer.singleShot(graceful_timeout_ms, lambda: self._kill_if_running(gen))
        if wait:
            if not self._proc.waitForFinished(graceful_timeout_ms):
                self._proc.kill()
                self._proc.waitForFinished(1000)

    def _kill_if_running(self, generation: int):
        # Ignore timers armed for an earlier run (e.g. Restart Network
        # relaunched the process before the old grace period expired).
        if generation == self._generation and self.is_running():
            self._proc.kill()

    def is_running(self) -> bool:
        return self._proc.state() != QProcess.NotRunning

    def is_ready(self) -> bool:
        """True once the process is running AND (if a ready_marker was
        given) that marker has actually been seen in its output. If no
        ready_marker was configured, this is the same as is_running()."""
        if not self.is_running():
            return False
        if self._ready_marker is None:
            return True
        return self._seen_ready

    def write_line(self, text: str):
        """Writes one line to the child's stdin, exactly as if a human had
        typed it and pressed Enter. Used for client.py / admin_console.py's
        interactive menus."""
        if not self.is_running():
            return
        self._proc.write((text.rstrip("\n") + "\n").encode("utf-8"))

    # -----------------------------------------------------------------
    # Output plumbing
    # -----------------------------------------------------------------
    def _on_ready_read(self):
        chunk = bytes(self._proc.readAllStandardOutput())
        if chunk:
            text = self._decoder.decode(chunk)
            if text:
                self.output_text.emit(text)
                if self._ready_marker is not None and not self._seen_ready and self._ready_marker in text:
                    self._seen_ready = True
                    self.state_changed.emit("ready")

    def _on_error(self, err):
        self.error_occurred.emit(self._proc.errorString())

    def _on_finished(self, exit_code, exit_status):
        if exit_status == QProcess.CrashExit and not self._stop_requested:
            self.state_changed.emit("crashed")
        else:
            self.state_changed.emit("stopped")
