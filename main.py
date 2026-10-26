"""
main.py -- WAF Network Security Simulator, Prototype 1, increment 2.

Increment 1 delivered the process-management layer and the four terminals.
Increment 2 adds (SRS 3.2-3.7):
  - Network Topology view (status colours from real process/DB signals)
  - Dossier Viewer with independent Merkle-integrity verification
  - Admin-derived status bar counts (parsed from 'status' / 'listusers')
  - Password-masked terminal input, colour-tagged logs, log export/clear
  - New Simulation, Restart Network, Documentation and the other
    previously-missing menu items
"""

from __future__ import annotations

import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from PySide6.QtCore import Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QDesktopServices, QKeySequence
from PySide6.QtWidgets import (
    QApplication, QDialog, QDockWidget, QFileDialog, QLabel, QMainWindow,
    QMessageBox, QPushButton, QTextBrowser, QToolBar, QVBoxLayout,
)

from controllers.backend_controllers import (
    AdminController, BackendController, ClientController, FirewallController,
)
from controllers.detector_controller import DetectorController
from gui.dialogs.detector_log_dialog import DetectorLogDialog
from gui.dialogs.server_config_dialog import ServerConfigDialog
from gui.dialogs.working_dir_dialog import WorkingDirectoryDialog
from gui.widgets.dossier_viewer import DossierViewer
from gui.widgets.terminal_widget import TerminalWidget
from gui.widgets.topology_widget import TopologyWidget
from utils.admin_status import AdminOutputParser
from utils.config_manager import SimulatorConfig

AUTO_REFRESH_MS = 10000

HELP_HTML = """
<h2>WAF Network Security Simulator &mdash; Quick guide</h2>
<ol>
<li><b>Edit &gt; Working Directory</b>: choose your SecureGateway project folder
    (all four processes share its <code>aegis_auth.db</code> and <code>aegis_dossier.json</code>).</li>
<li><b>Start Firewall</b>, then <b>Start Server</b> (a configuration dialog opens first;
    Mock Database Mode is the safe default and touches no real MySQL).</li>
<li>Wait until the Firewall node turns green (<i>Ready</i>), then <b>Connect Client</b>
    and/or <b>Open Admin Terminal</b>.</li>
<li>In the Client terminal use the menu numbers (1 register, 2 login, 4&ndash;10 tests).
    In the Admin terminal log in, then use <code>grant</code>, <code>revoke</code>,
    <code>revive</code>, <code>perms</code>, <code>listusers</code>, <code>status</code>, ...</li>
<li>The <b>Dossier Viewer</b> shows the firewall's audit log and independently verifies its hashes.</li>
</ol>
<h3>Tools &gt; Malicious Content Detector</h3>
<p><b>Start Malicious Content Detector</b> launches the detector's backend (FastAPI, port 8000)
and frontend (<code>npm run dev</code>, port 5173) and opens it in your browser once both answer.
The first run installs the frontend's npm packages, which can take a few minutes. It runs
independently of the firewall/server/client above. <b>Stop</b> (or closing the simulator) shuts
both down. <b>View Detector Logs</b> shows the output; it is also saved to
<code>logs/malicious_detector.log</code>.</p>
<h3>Status bar counts</h3>
<p>User/allowed/blocked counts come from the Admin console's own <code>status</code> and
<code>listusers</code> output. Log in to the Admin terminal, then use
<b>Security &gt; Refresh Admin Status</b> (or enable auto-refresh). The commands are echoed
in the Admin terminal so nothing is sent silently.</p>
<h3>Passwords</h3>
<p>When a prompt mentions <i>password</i>, the input box masks what you type and the terminal
echo shows <code>********</code>; passwords never appear in the log or in exports.</p>
<h3>Colours</h3>
<p>Red: blocked / denied / errors. Amber: warnings. Green: allowed / granted / success.
This is display only and never changes what the firewall decided.</p>
"""


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WAF Network Security Simulator -- Prototype 1")
        self.resize(1400, 850)

        self.config = SimulatorConfig.load()
        self._mysql_password = ""

        self.firewall_ctrl = FirewallController(self)
        self.backend_ctrl = BackendController(self)
        self.client_ctrl = ClientController(self)
        self.admin_ctrl = AdminController(self)
        self._controllers = (self.firewall_ctrl, self.backend_ctrl, self.client_ctrl, self.admin_ctrl)
        # Deliberately NOT part of self._controllers: it is an independent tool with its own
        # lifecycle (see controllers/detector_controller.py), not part of the firewall network.
        self.detector_ctrl = DetectorController(os.path.dirname(os.path.abspath(__file__)), self)
        self._detector_log_dialog = None

        self.admin_parser = AdminOutputParser()

        self._build_central()
        self._build_docks()
        self._build_menu_and_toolbar()
        self._build_status_bar()

        for ctrl in self._controllers:
            ctrl.state_changed.connect(self._refresh_actions)
        self.detector_ctrl.state_changed.connect(self._refresh_detector_actions)
        self.detector_ctrl.ready.connect(self._on_detector_ready)
        self.detector_ctrl.failed.connect(self._on_detector_failed)
        self.admin_ctrl.output_text.connect(self._on_admin_output)
        self.admin_ctrl.state_changed.connect(self._on_admin_state)
        self.backend_ctrl.output_text.connect(lambda _t: self._update_status_bar())

        self._auto_timer = QTimer(self)
        self._auto_timer.timeout.connect(lambda: self._refresh_admin_status(silent=True))

        self._refresh_actions()
        self._refresh_detector_actions()
        self.dossier_viewer.set_path(self.config.working_dir)
        self.topology.set_ports(self.config.firewall_port, self.config.backend_port)

        # Deferred so no modal dialog opens from inside __init__.
        QTimer.singleShot(0, self._maybe_prompt_working_dir)

    # -----------------------------------------------------------------
    # Layout
    # -----------------------------------------------------------------
    def _build_central(self):
        self.topology = TopologyWidget()
        self.setCentralWidget(self.topology)

    def _build_docks(self):
        self.firewall_terminal = TerminalWidget("Firewall Terminal", False, self.firewall_ctrl)
        self.server_terminal = TerminalWidget("Server Terminal", False, self.backend_ctrl)
        self.client_terminal = TerminalWidget("Client Terminal", True, self.client_ctrl)
        self.admin_terminal = TerminalWidget("Admin Terminal", True, self.admin_ctrl)
        self.terminals = (self.firewall_terminal, self.server_terminal,
                          self.client_terminal, self.admin_terminal)
        self.dossier_viewer = DossierViewer()

        self.topology.bind("FIREWALL", self.firewall_ctrl)
        self.topology.bind("SERVER", self.backend_ctrl)
        self.topology.bind("CLIENT", self.client_ctrl)

        specs = [
            ("Firewall Terminal", self.firewall_terminal, Qt.LeftDockWidgetArea),
            ("Client Terminal", self.client_terminal, Qt.LeftDockWidgetArea),
            ("Server Terminal", self.server_terminal, Qt.RightDockWidgetArea),
            ("Admin Terminal", self.admin_terminal, Qt.RightDockWidgetArea),
            ("Dossier Viewer", self.dossier_viewer, Qt.BottomDockWidgetArea),
        ]
        self.docks = {}
        for title, widget, area in specs:
            dock = QDockWidget(title, self)
            dock.setWidget(widget)
            dock.setObjectName(title.replace(" ", "_"))
            self.addDockWidget(area, dock)
            self.docks[title] = dock
        self.splitDockWidget(self.docks["Firewall Terminal"], self.docks["Client Terminal"], Qt.Vertical)
        self.splitDockWidget(self.docks["Server Terminal"], self.docks["Admin Terminal"], Qt.Vertical)
        self.resizeDocks([self.docks["Firewall Terminal"], self.docks["Server Terminal"]], [430, 430], Qt.Horizontal)
        self.resizeDocks([self.docks["Dossier Viewer"]], [240], Qt.Vertical)

    def _build_menu_and_toolbar(self):
        mb = self.menuBar()

        # ---- File
        file_menu = mb.addMenu("&File")
        self.act_new = QAction("New Simulation", self)
        self.act_new.setShortcut(QKeySequence.New)
        self.act_new.triggered.connect(self._new_simulation)
        self.act_export_all = QAction("Export All Logs...", self)
        self.act_export_all.triggered.connect(self._export_all_logs)
        act_exit = QAction("Exit", self)
        act_exit.triggered.connect(self.close)
        file_menu.addAction(self.act_new)
        file_menu.addAction(self.act_export_all)
        file_menu.addSeparator()
        file_menu.addAction(act_exit)

        # ---- Edit
        edit_menu = mb.addMenu("&Edit")
        act_wd = QAction("Working Directory...", self)
        act_wd.triggered.connect(lambda: self._prompt_working_dir(initial=False))
        act_cfg = QAction("Server Configuration...", self)
        act_cfg.triggered.connect(self._open_server_config)
        act_clear = QAction("Clear Logs", self)
        act_clear.triggered.connect(self._clear_all_logs)
        for a in (act_wd, act_cfg):
            edit_menu.addAction(a)
        edit_menu.addSeparator()
        edit_menu.addAction(act_clear)

        # ---- View
        view_menu = mb.addMenu("&View")
        for dock in self.docks.values():
            view_menu.addAction(dock.toggleViewAction())

        # ---- Network
        net = mb.addMenu("&Network")
        self.act_start_firewall = QAction("Start Firewall", self)
        self.act_start_firewall.triggered.connect(self._start_firewall)
        self.act_stop_firewall = QAction("Stop Firewall", self)
        self.act_stop_firewall.triggered.connect(self.firewall_ctrl.stop)
        self.act_start_server = QAction("Start Server", self)
        self.act_start_server.triggered.connect(self._start_server)
        self.act_stop_server = QAction("Stop Server", self)
        self.act_stop_server.triggered.connect(self.backend_ctrl.stop)
        self.act_connect_client = QAction("Connect Client", self)
        self.act_connect_client.triggered.connect(self._start_client)
        self.act_disconnect_client = QAction("Disconnect Client", self)
        self.act_disconnect_client.triggered.connect(self.client_ctrl.stop)
        self.act_restart = QAction("Restart Network", self)
        self.act_restart.triggered.connect(self._restart_network)
        for a in (self.act_start_firewall, self.act_stop_firewall, self.act_start_server,
                  self.act_stop_server, self.act_connect_client, self.act_disconnect_client):
            net.addAction(a)
        net.addSeparator()
        net.addAction(self.act_restart)

        # ---- Security
        sec = mb.addMenu("&Security")
        self.act_open_admin = QAction("Open Admin Terminal", self)
        self.act_open_admin.triggered.connect(self._start_admin)
        self.act_refresh_stats = QAction("Refresh Admin Status", self)
        self.act_refresh_stats.triggered.connect(lambda: self._refresh_admin_status(silent=False))
        self.act_auto_stats = QAction("Auto-refresh Admin Status (10 s)", self)
        self.act_auto_stats.setCheckable(True)
        self.act_auto_stats.toggled.connect(self._toggle_auto_refresh)
        act_view_dossier = QAction("View Dossier", self)
        act_view_dossier.triggered.connect(self._show_dossier)
        for a in (self.act_open_admin, self.act_refresh_stats, self.act_auto_stats):
            sec.addAction(a)
        sec.addSeparator()
        sec.addAction(act_view_dossier)

        # ---- Tools
        tools = mb.addMenu("&Tools")
        self.act_start_detector = QAction("Start Malicious Content Detector", self)
        self.act_start_detector.triggered.connect(self._start_detector)
        self.act_stop_detector = QAction("Stop Malicious Content Detector", self)
        self.act_stop_detector.triggered.connect(self._stop_detector)
        self.act_open_detector = QAction("Open Detector in Browser", self)
        self.act_open_detector.triggered.connect(self._open_detector_browser)
        self.act_detector_logs = QAction("View Detector Logs...", self)
        self.act_detector_logs.triggered.connect(self._show_detector_logs)
        tools.addAction(self.act_start_detector)
        tools.addAction(self.act_stop_detector)
        tools.addSeparator()
        tools.addAction(self.act_open_detector)
        tools.addAction(self.act_detector_logs)

        # ---- Help
        help_menu = mb.addMenu("&Help")
        act_doc = QAction("Documentation", self)
        act_doc.setShortcut(QKeySequence.HelpContents)
        act_doc.triggered.connect(self._show_documentation)
        act_about = QAction("About", self)
        act_about.triggered.connect(self._show_about)
        help_menu.addAction(act_doc)
        help_menu.addAction(act_about)

        # ---- Toolbar
        tb = QToolBar("Main")
        tb.setObjectName("MainToolbar")
        self.addToolBar(tb)
        for a in (self.act_start_firewall, self.act_stop_firewall):
            tb.addAction(a)
        tb.addSeparator()
        for a in (self.act_start_server, self.act_stop_server):
            tb.addAction(a)
        tb.addSeparator()
        for a in (self.act_connect_client, self.act_disconnect_client):
            tb.addAction(a)
        tb.addSeparator()
        tb.addAction(self.act_open_admin)
        tb.addAction(self.act_refresh_stats)

    def _build_status_bar(self):
        self.status_procs = QLabel("")
        self.status_stats = QLabel("")
        self.status_wd = QLabel("")
        self.statusBar().addWidget(self.status_procs, 1)
        self.statusBar().addPermanentWidget(self.status_stats)
        self.statusBar().addPermanentWidget(self.status_wd)
        self._update_status_bar()

    # -----------------------------------------------------------------
    # Process actions
    # -----------------------------------------------------------------
    def _require_working_dir(self) -> bool:
        problems = self.config.validate_working_dir()
        if problems:
            QMessageBox.warning(
                self, "Working directory required",
                "Set a valid working directory first (Edit > Working Directory...).\n\n" + "\n".join(problems))
            return False
        return True

    def _require_firewall_ready(self, what: str) -> bool:
        if self.firewall_ctrl.is_ready():
            return True
        QMessageBox.information(
            self, "Firewall not ready",
            f"Start the Firewall and wait for it to report ready before {what} "
            "(it must finish initializing its AI modules and bind its listening socket).")
        return False

    def _start_firewall(self):
        if self._require_working_dir():
            self.firewall_ctrl.launch(self.config)

    def _start_server(self):
        if not self._require_working_dir():
            return
        dlg = ServerConfigDialog(self.config, self)
        if not dlg.exec():
            return
        self._mysql_password = dlg.mysql_password()
        self.config.save()
        self.topology.set_ports(self.config.firewall_port, self.config.backend_port)
        self._update_status_bar()
        self.backend_ctrl.launch(self.config, mysql_password=self._mysql_password)

    def _start_client(self):
        if self._require_working_dir() and self._require_firewall_ready("connecting a Client"):
            self.client_ctrl.launch(self.config)

    def _start_admin(self):
        if self._require_working_dir() and self._require_firewall_ready("opening the Admin Terminal"):
            self.admin_ctrl.launch(self.config)
            self.docks["Admin Terminal"].raise_()

    # ---- Restart / New simulation
    def _stop_all(self):
        for c in (self.client_ctrl, self.admin_ctrl, self.firewall_ctrl, self.backend_ctrl):
            c.stop()

    def _restart_network(self):
        if not self._require_working_dir():
            return
        self._stop_all()
        deadline = time.monotonic() + 8.0
        timer = QTimer(self)

        def check():
            if any(c.is_running() for c in self._controllers):
                if time.monotonic() > deadline:
                    timer.stop()
                    QMessageBox.warning(self, "Restart Network",
                                        "Some processes did not stop in time; nothing was restarted.")
                return
            timer.stop()
            # Uses the last saved configuration (no dialog). A real-MySQL
            # password is kept in memory only, so after an application
            # restart Real MySQL Mode needs Start Server once to re-enter it.
            self.firewall_ctrl.launch(self.config)
            self.backend_ctrl.launch(self.config, mysql_password=self._mysql_password)

        timer.timeout.connect(check)
        timer.start(100)

    def _new_simulation(self):
        if QMessageBox.question(
            self, "New Simulation",
            "Stop all running processes and clear all terminals?\n"
            "(Settings and the dossier file are kept.)") != QMessageBox.Yes:
            return
        self._stop_all()
        self._clear_all_logs()
        self.admin_parser.reset()
        self._update_status_bar()

    # -----------------------------------------------------------------
    # Logs
    # -----------------------------------------------------------------
    def _clear_all_logs(self):
        for t in self.terminals:
            t.clear()

    def _export_all_logs(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Export all logs", "waf_simulator_logs.txt", "Text files (*.txt *.log);;All files (*)")
        if not path:
            return
        parts = [f"WAF Network Security Simulator -- log export {datetime.now().isoformat(timespec='seconds')}\n"]
        for t in self.terminals:
            parts.append(f"\n===== {t.title} =====\n{t.export_text()}\n")
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("".join(parts))
        except OSError as e:
            QMessageBox.critical(self, "Export failed", str(e))

    # -----------------------------------------------------------------
    # Admin status (parsed from the Admin console's own output)
    # -----------------------------------------------------------------
    def _on_admin_output(self, text: str):
        events = self.admin_parser.feed(text)
        if events:
            self._update_status_bar()

    def _on_admin_state(self, state: str):
        if state in ("stopped", "crashed"):
            self.admin_parser.reset()
            self._update_status_bar()

    def _refresh_admin_status(self, silent: bool):
        if not (self.admin_ctrl.is_running() and self.admin_parser.logged_in):
            if not silent:
                QMessageBox.information(
                    self, "Admin session needed",
                    "Open the Admin Terminal and log in first; the counts are read from the "
                    "Admin console's own 'status' and 'listusers' output.")
            return
        for cmd in ("status", "listusers"):
            self.admin_terminal.echo_sent(cmd)
            self.admin_ctrl.write_line(cmd)

    def _toggle_auto_refresh(self, on: bool):
        if on:
            self._auto_timer.start(AUTO_REFRESH_MS)
            self._refresh_admin_status(silent=True)
        else:
            self._auto_timer.stop()

    # -----------------------------------------------------------------
    # Dialogs / misc
    # -----------------------------------------------------------------
    def _maybe_prompt_working_dir(self):
        if not self.config.working_dir:
            self._prompt_working_dir(initial=True)

    def _prompt_working_dir(self, initial: bool):
        dlg = WorkingDirectoryDialog(self.config, self)
        if dlg.exec():
            self.config.save()
            self.dossier_viewer.set_path(self.config.working_dir)
            self._update_status_bar()
        elif initial:
            QMessageBox.information(
                self, "Working directory not set",
                "You can set it later via Edit > Working Directory..., but the start "
                "actions stay unavailable until then.")

    def _open_server_config(self):
        dlg = ServerConfigDialog(self.config, self)
        if dlg.exec():
            self._mysql_password = dlg.mysql_password()
            self.config.save()
            self.topology.set_ports(self.config.firewall_port, self.config.backend_port)
            self._update_status_bar()

    def _show_dossier(self):
        dock = self.docks["Dossier Viewer"]
        dock.show()
        dock.raise_()
        self.dossier_viewer.refresh(force=True)

    # -----------------------------------------------------------------
    # Tools > Malicious Content Detector
    # -----------------------------------------------------------------
    def _start_detector(self):
        self.statusBar().showMessage("Starting Malicious Content Detector...", 5000)
        self.detector_ctrl.start()

    def _stop_detector(self):
        self.detector_ctrl.stop(wait=True)
        self.statusBar().showMessage("Malicious Content Detector stopped", 5000)

    def _open_detector_browser(self):
        if self.detector_ctrl.is_running():
            QDesktopServices.openUrl(QUrl(self.detector_ctrl.frontend_url()))

    def _show_detector_logs(self):
        if self._detector_log_dialog is None:
            self._detector_log_dialog = DetectorLogDialog(self.detector_ctrl, self)
        self._detector_log_dialog.show()
        self._detector_log_dialog.raise_()
        self._detector_log_dialog.activateWindow()

    def _refresh_detector_actions(self, *_):
        idle = self.detector_ctrl.is_idle()
        self.act_start_detector.setEnabled(idle)
        self.act_stop_detector.setEnabled(not idle)
        self.act_open_detector.setEnabled(self.detector_ctrl.is_running())
        self._update_status_bar()

    def _on_detector_ready(self, url: str):
        opened = QDesktopServices.openUrl(QUrl(url))
        self.statusBar().showMessage(
            f"Malicious Content Detector is running at {url}" if opened else
            f"Malicious Content Detector is running -- open {url} in your browser", 10000)

    def _on_detector_failed(self, title: str, details: str):
        head, _, tail = details.partition("\n\nLast log lines:\n")
        box = QMessageBox(QMessageBox.Critical, title, title, QMessageBox.NoButton, self)
        box.setInformativeText(head)
        if tail:
            box.setDetailedText(tail)
        logs_btn = box.addButton("View Logs", QMessageBox.ActionRole)
        box.addButton(QMessageBox.Close)
        box.exec()
        if box.clickedButton() is logs_btn:
            self._show_detector_logs()

    def _show_documentation(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Documentation")
        dlg.resize(640, 560)
        lay = QVBoxLayout(dlg)
        browser = QTextBrowser()
        browser.setHtml(HELP_HTML)
        lay.addWidget(browser)
        close = QPushButton("Close")
        close.clicked.connect(dlg.accept)
        lay.addWidget(close)
        dlg.exec()

    def _show_about(self):
        QMessageBox.information(
            self, "About",
            "WAF Network Security Simulator -- Prototype 1\n\n"
            "A PySide6 control and visualization layer over the existing SecureGateway "
            "CLI backend, which runs unmodified as managed subprocesses.")

    # -----------------------------------------------------------------
    # State -> UI
    # -----------------------------------------------------------------
    def _refresh_actions(self, *_):
        fw_running = self.firewall_ctrl.is_running()
        fw_ready = self.firewall_ctrl.is_ready()
        srv_running = self.backend_ctrl.is_running()
        client_running = self.client_ctrl.is_running()
        admin_running = self.admin_ctrl.is_running()
        self.act_start_firewall.setEnabled(not fw_running)
        self.act_stop_firewall.setEnabled(fw_running)
        self.act_start_server.setEnabled(not srv_running)
        self.act_stop_server.setEnabled(srv_running)
        self.act_connect_client.setEnabled(not client_running and fw_ready)
        self.act_disconnect_client.setEnabled(client_running)
        self.act_open_admin.setEnabled(not admin_running and fw_ready)
        self.act_refresh_stats.setEnabled(admin_running)
        self._update_status_bar()

    @staticmethod
    def _proc_word(ctrl) -> str:
        if not ctrl.is_running():
            return "offline"
        if ctrl.awaits_ready:
            return "ready" if ctrl.is_ready() else "starting"
        return "running"

    def _update_status_bar(self):
        admin_word = "logged in" if self.admin_parser.logged_in else self._proc_word(self.admin_ctrl)
        self.status_procs.setText(
            f"Firewall: {self._proc_word(self.firewall_ctrl)}  |  "
            f"Server: {self._proc_word(self.backend_ctrl)}  |  "
            f"MySQL: {self.topology._db_status[0]}  |  "
            f"Client: {self._proc_word(self.client_ctrl)}  |  "
            f"Admin: {admin_word}  |  "
            f"Detector: {self.detector_ctrl.status_word()}")
        if self.admin_parser.logged_in:
            self.status_stats.setText(self.admin_parser.stats.summary())
        else:
            self.status_stats.setText("Admin counts: n/a (log in to Admin)")
        wd = self.config.working_dir
        engine = "Mock (safe)" if self.config.db_engine == "mock" else f"Real MySQL @ {self.config.mysql_host}"
        if wd:
            folder = os.path.basename(os.path.normpath(wd)) or wd
        else:
            folder = "(not set)"
        self.status_wd.setText("  Dir: " + folder + "  |  DB: " + engine)
        self.status_wd.setToolTip(wd or "Working directory not set")

    # -----------------------------------------------------------------
    def closeEvent(self, event):
        self._auto_timer.stop()
        for c in (self.client_ctrl, self.admin_ctrl, self.firewall_ctrl, self.backend_ctrl):
            c.stop(wait=True)
        self.detector_ctrl.stop(wait=True)   # also kills npm/vite's child processes
        event.accept()


def main():
    app = QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
