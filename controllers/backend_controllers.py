"""
backend_controllers.py -- one thin ProcessController subclass per backend
program, each responsible only for building that script's argv from a
SimulatorConfig. No process logic lives here beyond argument construction;
everything else is inherited from ProcessController.
"""

from __future__ import annotations

import os
from typing import Optional

from controllers.process_controller import ProcessController
from utils.config_manager import SimulatorConfig

# Root of this GUI project (controllers/ -> project root), used to locate
# GUI-side helper scripts that are NOT part of the backend project itself.
_GUI_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ADMIN_LAUNCHER_PATH = os.path.join(_GUI_ROOT, "gui_helpers", "admin_console_launcher.py")


class FirewallController(ProcessController):
    """Wraps aegis_firewall.py -- takes no stdin, no CLI arguments of its
    own today; started with the shared working directory as its cwd so it
    finds/creates aegis_auth.db and aegis_dossier.json in the same place
    every other process uses."""

    def __init__(self, parent=None):
        super().__init__("Firewall", parent)

    def launch(self, config: SimulatorConfig):
        self.start(
            script_path=config.script_path("aegis_firewall.py"),
            args=[],
            working_dir=config.working_dir,
            ready_marker="AI Security Modules Online",
        )


class BackendController(ProcessController):
    """Wraps server.py -- the only backend file with an intentional,
    minimal modification (Section 2.3/2.4 of the SRS): DB engine + MySQL
    connection are argv-driven instead of hardcoded, defaulting to the
    sandboxed mock engine so no real MySQL install is ever required or
    touched unless the operator explicitly opts into Real MySQL Mode."""

    def __init__(self, parent=None):
        super().__init__("Server", parent)

    def launch(self, config: SimulatorConfig, mysql_password: Optional[str] = None):
        args = [
            "--host", config.backend_host,
            "--port", str(config.backend_port),
            "--db-engine", config.db_engine,
            "--working-dir", config.working_dir,
        ]
        if config.db_engine == "mysql":
            args += [
                "--mysql-host", config.mysql_host,
                "--mysql-port", str(config.mysql_port),
                "--mysql-user", config.mysql_user,
                "--mysql-database", config.mysql_database,
            ]
        env = None
        if config.db_engine == "mysql" and mysql_password is not None:
            # Passed via environment for this one launch only -- never
            # written to disk, never placed on the command line where it
            # could be visible in a process list.
            env = {"SG_MYSQL_PASSWORD": mysql_password}
        self.start(
            script_path=config.script_path("server.py"),
            args=args,
            working_dir=config.working_dir,
            env=env,
            ready_marker="Sandbox directory:",
        )


class ClientController(ProcessController):
    """Wraps client.py -- interactive; the GUI drives its numbered menu by
    writing the same keystrokes a human would type via write_line()."""

    def __init__(self, parent=None):
        super().__init__("Client", parent)

    def launch(self, config: SimulatorConfig):
        self.start(
            script_path=config.script_path("client.py"),
            args=[],
            working_dir=config.working_dir,
        )


class AdminController(ProcessController):
    """Wraps admin_console.py -- interactive; same stdin-driving approach
    as ClientController.

    Launched via admin_console_launcher.py (a GUI-side shim, not a change
    to admin_console.py itself) so that its admin-password prompt --
    which uses getpass.getpass(), unlike client.py's plain input() for its
    password -- goes through this GUI's Admin Terminal input box instead
    of bypassing the pipe to grab whatever real console/tty this whole
    application happens to be attached to. See admin_console_launcher.py's
    module docstring for the full explanation."""

    def __init__(self, parent=None):
        super().__init__("Admin", parent)

    def launch(self, config: SimulatorConfig):
        self.start(
            script_path=_ADMIN_LAUNCHER_PATH,
            args=[],
            working_dir=config.working_dir,
        )
