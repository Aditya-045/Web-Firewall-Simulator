"""
server_config_dialog.py -- implements SRS Section 2.4: Mock Database Mode
is the default and is pre-selected/highlighted as "safe"; Real MySQL Mode
requires an explicit switch plus a one-time confirmation, and its "Test
Connection" only ever issues SELECT 1 -- never CREATE DATABASE, never an
installer, never a service start/stop call.
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QGroupBox, QRadioButton,
    QLineEdit, QSpinBox, QPushButton, QLabel, QDialogButtonBox, QMessageBox
)

from utils.config_manager import SimulatorConfig


class ServerConfigDialog(QDialog):
    def __init__(self, config: SimulatorConfig, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Server Configuration")
        self.config = config
        self._mysql_password = ""

        layout = QVBoxLayout(self)

        net_group = QGroupBox("Backend listen address")
        net_form = QFormLayout(net_group)
        self.host_edit = QLineEdit(config.backend_host)
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(config.backend_port)
        net_form.addRow("Host:", self.host_edit)
        net_form.addRow("Port:", self.port_spin)
        layout.addWidget(net_group)

        engine_group = QGroupBox("Database engine")
        engine_layout = QVBoxLayout(engine_group)

        self.mock_radio = QRadioButton(
            "Mock Database Mode (default) -- Safe: no local MySQL required or affected"
        )
        self.mock_radio.setStyleSheet("font-weight: 600; color: #2F7A4D;")
        engine_layout.addWidget(self.mock_radio)
        engine_layout.addWidget(QLabel(
            "    Uses a disposable SQLite file inside your working directory.\n"
            "    Nothing on this computer's real MySQL installation (if any) is touched."
        ))

        self.mysql_radio = QRadioButton("Use a real MySQL server (opt-in, advanced)")
        engine_layout.addWidget(self.mysql_radio)

        mysql_box = QGroupBox()
        mysql_form = QFormLayout(mysql_box)
        self.mysql_host_edit = QLineEdit(config.mysql_host)
        self.mysql_port_spin = QSpinBox()
        self.mysql_port_spin.setRange(1, 65535)
        self.mysql_port_spin.setValue(config.mysql_port)
        self.mysql_db_edit = QLineEdit(config.mysql_database)
        self.mysql_user_edit = QLineEdit(config.mysql_user)
        self.mysql_pass_edit = QLineEdit()
        self.mysql_pass_edit.setEchoMode(QLineEdit.Password)
        self.mysql_pass_edit.setPlaceholderText("(not saved to disk)")
        mysql_form.addRow("Host:", self.mysql_host_edit)
        mysql_form.addRow("Port:", self.mysql_port_spin)
        mysql_form.addRow("Database:", self.mysql_db_edit)
        mysql_form.addRow("Username:", self.mysql_user_edit)
        mysql_form.addRow("Password:", self.mysql_pass_edit)

        test_row = QHBoxLayout()
        self.test_btn = QPushButton("Test Connection (SELECT 1 only)")
        self.test_btn.clicked.connect(self._test_connection)
        self.provision_btn = QPushButton("Provision sandbox tables in this schema")
        self.provision_btn.setToolTip(
            "Only creates gdp_data / brics_debt_trade IF they do not already exist "
            "in the schema you named above. Never touches any other schema."
        )
        self.provision_btn.clicked.connect(self._provision_tables)
        test_row.addWidget(self.test_btn)
        test_row.addWidget(self.provision_btn)
        mysql_form.addRow(test_row)

        engine_layout.addWidget(mysql_box)
        layout.addWidget(engine_group)

        self.mock_radio.toggled.connect(lambda on: mysql_box.setEnabled(not on))
        (self.mock_radio if config.db_engine == "mock" else self.mysql_radio).setChecked(True)
        mysql_box.setEnabled(config.db_engine == "mysql")

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    # -----------------------------------------------------------------
    def _current_mysql_fields(self) -> SimulatorConfig:
        c = SimulatorConfig(
            working_dir=self.config.working_dir,
            mysql_host=self.mysql_host_edit.text(),
            mysql_port=self.mysql_port_spin.value(),
            mysql_database=self.mysql_db_edit.text(),
            mysql_user=self.mysql_user_edit.text(),
        )
        return c

    def _test_connection(self):
        try:
            import mysql.connector
        except ImportError:
            QMessageBox.warning(self, "Not installed", "mysql-connector-python is not installed.")
            return
        c = self._current_mysql_fields()
        try:
            conn = mysql.connector.connect(
                host=c.mysql_host, port=c.mysql_port, user=c.mysql_user,
                password=self.mysql_pass_edit.text(), database=c.mysql_database,
                connection_timeout=4,
            )
            cur = conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchall()
            cur.close()
            conn.close()
            QMessageBox.information(self, "Connection OK", "Connected and ran SELECT 1 successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Connection failed", str(e))

    def _provision_tables(self):
        if QMessageBox.question(
            self, "Confirm",
            "This will run CREATE TABLE IF NOT EXISTS for gdp_data and "
            "brics_debt_trade in the schema you named above, only if they "
            "don't already exist. No other schema or table is touched. Continue?",
        ) != QMessageBox.Yes:
            return
        try:
            import mysql.connector
            c = self._current_mysql_fields()
            conn = mysql.connector.connect(
                host=c.mysql_host, port=c.mysql_port, user=c.mysql_user,
                password=self.mysql_pass_edit.text(), database=c.mysql_database,
                connection_timeout=4,
            )
            cur = conn.cursor()
            cur.execute("""CREATE TABLE IF NOT EXISTS gdp_data (
                country_id VARCHAR(8), country_name VARCHAR(64),
                year INT, gdp_usd_billion DOUBLE)""")
            cur.execute("""CREATE TABLE IF NOT EXISTS brics_debt_trade (
                country_id VARCHAR(8), debt_to_gdp_pct DOUBLE,
                trade_balance_usd_billion DOUBLE)""")
            conn.commit()
            cur.close()
            conn.close()
            QMessageBox.information(self, "Done", "Sandbox tables ensured in the named schema.")
        except Exception as e:
            QMessageBox.critical(self, "Failed", str(e))

    def _on_accept(self):
        self.config.backend_host = self.host_edit.text()
        self.config.backend_port = self.port_spin.value()

        if self.mysql_radio.isChecked():
            if QMessageBox.question(
                self, "Use a real MySQL server?",
                "This will connect to an existing MySQL server you specify.\n"
                "The simulator will not create, alter, or drop databases other "
                "than the schema you name.\n\nContinue?",
            ) != QMessageBox.Yes:
                return
            self.config.db_engine = "mysql"
            self.config.mysql_host = self.mysql_host_edit.text()
            self.config.mysql_port = self.mysql_port_spin.value()
            self.config.mysql_database = self.mysql_db_edit.text()
            self.config.mysql_user = self.mysql_user_edit.text()
            self._mysql_password = self.mysql_pass_edit.text()
        else:
            self.config.db_engine = "mock"
            self._mysql_password = ""

        self.accept()

    def mysql_password(self) -> str:
        """Session-only; the dialog never persists this anywhere."""
        return self._mysql_password
