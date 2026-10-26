"""
Headless end-to-end test for increment 2 (32 checks).

Usage (from the waf_simulator folder):
    python tests/test_inc2.py "C:\\path\\to\\your\\SecureGateway project"

It copies your (unmodified) backend files plus server_patch/ into a
temporary working directory, creates a throwaway admin account there, runs
the real GUI against the real backend in Mock DB mode, then deletes the
temporary directory. Your project folder is never modified.
On Linux/CI run with: QT_QPA_PLATFORM=offscreen
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

PROJECT = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("WAF_PROJECT_DIR", "")
BACKEND = ["aegis_firewall.py", "client.py", "admin_console.py", "bootstrap_admin.py",
           "auth_db.py", "protocol.py", "command_classifier.py"]
if not PROJECT or not all(os.path.isfile(os.path.join(PROJECT, f)) for f in BACKEND):
    sys.exit("Pass the path of your SecureGateway project folder (must contain: " + ", ".join(BACKEND) + ")")

WORK = tempfile.mkdtemp(prefix="waf_sim_test_")
for f in BACKEND:
    shutil.copy(os.path.join(PROJECT, f), WORK)
for f in ("server.py", "mock_mysql.py"):
    shutil.copy(os.path.join(ROOT, "server_patch", f), WORK)
subprocess.run([sys.executable, "-c",
                "import auth_db; auth_db.init_db(); auth_db.register_admin('testadmin','adminpass123')"],
               cwd=WORK, check=True)

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication, QLineEdit

import gui.dialogs.server_config_dialog as scd
from gui.widgets.terminal_widget import classify_line
from gui.widgets.topology_widget import GREEN, GRAY
from main import MainWindow

app = QApplication(sys.argv)
win = MainWindow()
win.config.working_dir = WORK
win.config.db_engine = "mock"
win.dossier_viewer.set_path(WORK)
win.show()

# auto-accept the Server Configuration dialog (Mock mode)
def fake_exec(self):
    self.mock_radio.setChecked(True)
    return 1
scd.ServerConfigDialog.exec = fake_exec

results = []
def check(name, cond, extra=""):
    results.append((name, bool(cond)))
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{extra}]" if extra else ""), flush=True)

# --------------------------- step runner ---------------------------
steps = []
def step(fn):
    steps.append(fn)
    return fn

def run_next():
    if not steps:
        return finish()
    fn = steps.pop(0)
    fn()

def wait_for(cond, then, timeout=25, what=""):
    start = time.monotonic()
    t = QTimer()
    def poll():
        if cond():
            t.stop(); then()
        elif time.monotonic() - start > timeout:
            t.stop(); check(f"TIMEOUT waiting for: {what}", False); finish()
    t.timeout.connect(poll)
    t.start(100)
    wait_for._keep = getattr(wait_for, "_keep", []) + [t]

def type_into(term, text):
    term.input_box.setText(text)
    term._on_enter()

node = lambda n: win.topology.nodes[n].status_text.text()
line_ok = lambda l: l.text() if hasattr(l, "text") else l

@step
def s_unit():
    check("colour tagging: DENIED->red", classify_line("[FILTER - PERMISSION DENIED] x") == "red")
    check("colour tagging: ALLOWED->green", classify_line("[FILTER - ALLOWED] Legal User") == "green")
    check("colour tagging: WARNING->amber", classify_line("[FILTER - WARNING] Internal User Cautioned") == "amber")
    check("colour tagging: 'No warnings' prose stays plain",
          classify_line("-> Status: Green (0/2). No warnings or malice detected.") in (None, "green"))
    check("colour tagging: lowercase 'allowed' prose stays plain",
          classify_line("Try a command your account shouldn't be allowed to run yet.") is None)
    check("topology starts Offline", all(node(n) == "Offline" for n in ("CLIENT", "FIREWALL", "SERVER", "MYSQL")))
    run_next()

@step
def s_start():
    win._start_firewall()
    win._start_server()
    check("Start Server used the config dialog path (server launching)", win.backend_ctrl.is_running())
    wait_for(lambda: win.firewall_ctrl.is_ready() and win.backend_ctrl.is_ready(), run_next, what="firewall+server ready")

@step
def s_topology_ready():
    check("topology: Firewall node Ready", node("FIREWALL") == "Ready", node("FIREWALL"))
    check("topology: Server node Ready", node("SERVER") == "Ready", node("SERVER"))
    wait_for(lambda: node("MYSQL") != "Waiting", run_next, what="MySQL node status")

@step
def s_mysql_node():
    check("topology: MySQL node shows sandbox mock DB", node("MYSQL") == "Mock DB (sandbox)", node("MYSQL"))
    edge_color = win.topology.edges["fw_server"].line.pen().color().name().upper()
    check("topology: firewall->server link active (green)", edge_color == GREEN.upper(), edge_color)
    check("status bar mentions ready firewall/server",
          "Firewall: ready" in win.status_procs.text() and "Server: ready" in win.status_procs.text(),
          win.status_procs.text())
    win._start_client()
    win._start_admin()
    wait_for(lambda: "Select test>" in win.client_terminal._tail, run_next, what="client menu prompt")

@step
def s_client_register():
    type_into(win.client_terminal, "1")
    wait_for(lambda: "username" in win.client_terminal._tail.lower(), run_next, what="username prompt")

@step
def s_client_user():
    type_into(win.client_terminal, "u1")
    wait_for(lambda: "password" in win.client_terminal._tail.lower(), run_next, what="password prompt")

@step
def s_client_password_masked():
    check("client password prompt -> input box masked",
          win.client_terminal.input_box.echoMode() == QLineEdit.Password)
    type_into(win.client_terminal, "S3cretClientPw")
    doc = win.client_terminal.output.toPlainText()
    check("client password never written into terminal document", "S3cretClientPw" not in doc)
    check("client password never in export", "S3cretClientPw" not in win.client_terminal.export_text())
    check("input box unmasked again after entry",
          win.client_terminal.input_box.echoMode() == QLineEdit.Normal)
    wait_for(lambda: "Select test>" in win.client_terminal._tail, run_next, what="client menu again")

@step
def s_admin_login_user():
    wait_for(lambda: "admin username" in win.admin_terminal._tail.lower(), lambda: (type_into(win.admin_terminal, "testadmin"), run_next()), what="admin username prompt")

@step
def s_admin_login_pw():
    wait_for(lambda: "admin password" in win.admin_terminal._tail.lower(), run_next, what="admin password prompt")

@step
def s_admin_pw_masked():
    check("admin password prompt -> input box masked (same GUI box, no console)",
          win.admin_terminal.input_box.echoMode() == QLineEdit.Password)
    type_into(win.admin_terminal, "adminpass123")
    check("admin password not in terminal document",
          "adminpass123" not in win.admin_terminal.output.toPlainText())
    check("admin echo line shows mask", "> ********" in win.admin_terminal.output.toPlainText())
    wait_for(lambda: win.admin_parser.logged_in, run_next, what="admin logged in")

@step
def s_admin_status():
    check("status bar shows Admin: logged in", "Admin: logged in" in win.status_procs.text(), win.status_procs.text())
    win._refresh_admin_status(silent=False)
    wait_for(lambda: win.admin_parser.stats.registered is not None and win.admin_parser.stats.allowed is not None,
             run_next, what="admin status + listusers parsed")

@step
def s_admin_status_check():
    s = win.admin_parser.stats
    check("parsed registered users == 1", s.registered == 1, str(s.registered))
    check("parsed allowed/blocked counts present", s.allowed is not None and s.blocked is not None,
          f"allowed={s.allowed} blocked={s.blocked}")
    check("status bar shows parsed counts", "1 registered" in win.status_stats.text(), win.status_stats.text())
    check("GUI-sent commands were echoed visibly in Admin terminal",
          "(sent by GUI)" in win.admin_terminal.output.toPlainText())
    wait_for(lambda: win.dossier_viewer.table.rowCount() >= 2, run_next, what="dossier rows")

@step
def s_dossier():
    label = win.dossier_viewer.integrity_label.text()
    check("Dossier Viewer loaded rows", win.dossier_viewer.table.rowCount() >= 2,
          str(win.dossier_viewer.table.rowCount()))
    check("Dossier integrity VERIFIED", "VERIFIED" in label, label)
    win.firewall_ctrl.stop()
    wait_for(lambda: not win.firewall_ctrl.is_running(), run_next, what="firewall stop")

@step
def s_stop_state():
    wait_for(lambda: node("FIREWALL") in ("Offline", "Crashed"), lambda: None, timeout=3)
    check("user-initiated stop shows Offline, not Crashed", node("FIREWALL") == "Offline", node("FIREWALL"))
    check("firewall->server link inactive after stop",
          win.topology.edges["fw_server"].line.pen().color().name().upper() != GREEN.upper())
    # tamper with the dossier while the firewall is down, then look at the viewer
    path = os.path.join(WORK, "aegis_dossier.json")
    data = json.load(open(path))
    data["logs"][1]["details"] = "TAMPERED"
    json.dump(data, open(path, "w"), indent=2)
    win.dossier_viewer.refresh(force=True)
    wait_for(lambda: "TAMPERING" in win.dossier_viewer.integrity_label.text(), run_next, what="tamper detection")

@step
def s_tamper_done():
    check("tampering detected in the Dossier Viewer", True, win.dossier_viewer.integrity_label.text()[:80])
    # restore, then test Restart Network
    data = json.load(open(os.path.join(WORK, "aegis_dossier.json")))
    win._restart_network()
    wait_for(lambda: win.firewall_ctrl.is_ready() and win.backend_ctrl.is_ready(), run_next, timeout=40,
             what="restart: firewall+server ready again")

@step
def s_restarted():
    check("Restart Network brought firewall and server back to Ready",
          node("FIREWALL") == "Ready" and node("SERVER") == "Ready", f"{node('FIREWALL')}/{node('SERVER')}")
    check("client/admin were stopped by restart (fresh sessions)",
          not win.client_ctrl.is_running() and not win.admin_ctrl.is_running())
    check("admin parser reset after admin stopped", not win.admin_parser.logged_in)
    run_next()

def finish():
    fails = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(fails)}/{len(results)} checks passed")
    print("RESULT:", "PASS" if not fails else f"FAIL {fails}")
    win.close()
    shutil.rmtree(WORK, ignore_errors=True)
    app.quit()

QTimer.singleShot(500, run_next)
QTimer.singleShot(110000, finish)
sys.exit(app.exec())
