"""
detector_log_dialog.py -- live log window for the Malicious Content Detector.

Shows everything the DetectorController has logged for the current run (its
own [detector] lines plus the backend's / frontend's / npm's output) and keeps
following new lines. Non-modal, so it can stay open while you use the tool.
The same text is written to <simulator dir>/logs/malicious_detector.log.
"""
from __future__ import annotations

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices, QFont
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QPlainTextEdit, QPushButton, QVBoxLayout,
)


class DetectorLogDialog(QDialog):
    def __init__(self, controller, parent=None):
        super().__init__(parent)
        self._ctrl = controller
        self.setWindowTitle("Malicious Content Detector -- Logs")
        self.resize(900, 520)

        lay = QVBoxLayout(self)
        self._path_label = QLabel("")
        self._path_label.setWordWrap(True)
        lay.addWidget(self._path_label)

        self._view = QPlainTextEdit()
        self._view.setReadOnly(True)
        self._view.setMaximumBlockCount(5000)
        self._view.setLineWrapMode(QPlainTextEdit.NoWrap)
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.Monospace)
        self._view.setFont(mono)
        lay.addWidget(self._view, 1)

        row = QHBoxLayout()
        self._open_btn = QPushButton("Open log file")
        self._open_btn.clicked.connect(self._open_file)
        clear_btn = QPushButton("Clear view")
        clear_btn.clicked.connect(self._view.clear)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        row.addWidget(self._open_btn)
        row.addWidget(clear_btn)
        row.addStretch(1)
        row.addWidget(close_btn)
        lay.addLayout(row)

        controller.log_line.connect(self._view.appendPlainText)
        controller.state_changed.connect(lambda _s: self._sync())

    def showEvent(self, event):
        # Re-populate from the controller's buffer so lines logged while the
        # window was closed are not lost.
        self._view.setPlainText("\n".join(self._ctrl.log_lines()))
        self._sync()
        super().showEvent(event)

    def _sync(self):
        p = self._ctrl.log_path()
        self._path_label.setText(f"Log file: {p}" if p else "Log file: (none yet -- start the detector)")
        self._open_btn.setEnabled(bool(p) and p.is_file())

    def _open_file(self):
        p = self._ctrl.log_path()
        if p and p.is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(p)))
