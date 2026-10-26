"""
working_dir_dialog.py -- lets the operator choose the shared folder that
must contain the (unmodified) backend scripts plus aegis_auth.db /
aegis_dossier.json. This is the folder every launched QProcess uses as its
working directory, so logins/grants/dossier entries all agree with each
other (see auth_db.py's own comment about this exact failure mode).
"""

from __future__ import annotations

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QPushButton,
    QFileDialog, QMessageBox, QDialogButtonBox
)

from utils.config_manager import SimulatorConfig


class WorkingDirectoryDialog(QDialog):
    def __init__(self, config: SimulatorConfig, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Working Directory")
        self.config = config

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(
            "Choose the folder containing your SecureGateway project\n"
            "(aegis_firewall.py, server.py, client.py, admin_console.py, ...).\n"
            "All four simulated processes will be launched from this exact\n"
            "folder, so they share the same aegis_auth.db and aegis_dossier.json."
        ))

        row = QHBoxLayout()
        self.path_edit = QLineEdit(config.working_dir)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse)
        row.addWidget(self.path_edit, 1)
        row.addWidget(browse_btn)
        layout.addLayout(row)

        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._on_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.path_edit.textChanged.connect(self._revalidate)
        self._revalidate()

    def _browse(self):
        path = QFileDialog.getExistingDirectory(self, "Select working directory", self.path_edit.text())
        if path:
            self.path_edit.setText(path)

    def _revalidate(self):
        candidate = SimulatorConfig(working_dir=self.path_edit.text())
        problems = candidate.validate_working_dir()
        if not problems:
            self.status_label.setText("Looks good -- all expected backend files were found.")
            self.status_label.setStyleSheet("color: #2F7A4D;")
        else:
            self.status_label.setText("\n".join(problems))
            self.status_label.setStyleSheet("color: #B23A2F;")

    def _on_accept(self):
        candidate = SimulatorConfig(working_dir=self.path_edit.text())
        problems = candidate.validate_working_dir()
        if problems:
            resp = QMessageBox.question(
                self, "Continue anyway?",
                "This folder is missing some expected files:\n\n" + "\n".join(problems) +
                "\n\nUse it anyway?",
            )
            if resp != QMessageBox.Yes:
                return
        self.config.working_dir = self.path_edit.text()
        self.accept()
