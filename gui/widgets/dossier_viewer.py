"""
dossier_viewer.py -- read-only view of aegis_dossier.json (SRS 3.6).

The file is read and verified on a worker thread (QThreadPool) so a large
dossier can never stall the GUI, and it is polled by (mtime, size) rather
than a file-watcher because the firewall truncates and rewrites the whole
file on every event, which makes watchers unreliable across platforms.
"""

from __future__ import annotations

import os
from typing import Optional

from PySide6.QtCore import QObject, QRunnable, QThreadPool, QTimer, Signal, Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QPushButton, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from utils.dossier_reader import DossierResult, load_and_verify

COLUMNS = ["ID", "Time", "Type", "Source", "AI conf.", "Details"]
POLL_MS = 1500


def severity_color(event_type: str) -> Optional[str]:
    t = event_type.upper()
    if t.endswith("_RED") or "FAILED" in t or "DENIED" in t or "BLOCKED" in t or "ATTACK" in t:
        return "#B23A2F"
    if t.endswith("_ORANGE"):
        return "#B7791F"
    if t.endswith("_GREEN") or "SUCCESS" in t or t in ("ADMIN_GRANT", "ADMIN_REVIVE", "USER_REGISTERED"):
        return "#2F7A4D"
    return None


class _Signals(QObject):
    done = Signal(object)   # DossierResult


class _LoadTask(QRunnable):
    def __init__(self, path: str, signals: _Signals):
        super().__init__()
        self.path = path
        self.signals = signals

    def run(self):
        self.signals.done.emit(load_and_verify(self.path))


class DossierViewer(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._path = ""
        self._last_sig: Optional[tuple] = None
        self._loading = False
        self._signals = _Signals()
        self._signals.done.connect(self._on_loaded)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        top = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh")
        self.refresh_btn.clicked.connect(lambda: self.refresh(force=True))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter by text (type, user, command...)")
        self.filter_edit.textChanged.connect(self._apply_filter)
        top.addWidget(self.refresh_btn)
        top.addWidget(self.filter_edit, 1)
        layout.addLayout(top)

        self.integrity_label = QLabel("Integrity: (no dossier loaded)")
        self.integrity_label.setStyleSheet("font-weight: 600; color: #5C6270;")
        self.root_label = QLabel("")
        self.root_label.setStyleSheet("font-family: monospace; color: #5C6270;")
        self.root_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.integrity_label)
        layout.addWidget(self.root_label)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.verticalHeader().setVisible(False)
        hdr = self.table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.ResizeToContents)
        hdr.setStretchLastSection(True)
        layout.addWidget(self.table, 1)

        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(POLL_MS)

    # -----------------------------------------------------------------
    def set_path(self, working_dir: str):
        self._path = os.path.join(working_dir, "aegis_dossier.json") if working_dir else ""
        self._last_sig = None
        self.refresh(force=True)

    def refresh(self, force: bool = False):
        if not self._path or self._loading:
            return
        try:
            st = os.stat(self._path)
            sig = (st.st_mtime_ns, st.st_size)
        except OSError:
            sig = None
        if not force and sig == self._last_sig:
            return
        self._last_sig = sig
        self._loading = True
        QThreadPool.globalInstance().start(_LoadTask(self._path, self._signals))

    def _on_loaded(self, res: DossierResult):
        self._loading = False
        if not res.ok:
            self.table.setRowCount(0)
            self.integrity_label.setText(f"Integrity: {res.error}")
            self.integrity_label.setStyleSheet("font-weight: 600; color: #5C6270;")
            self.root_label.setText("")
            if "Could not read" in res.error:
                self._last_sig = None   # likely a half-written file; retry next poll
            return

        self.table.setRowCount(len(res.logs))
        for r, e in enumerate(res.logs):
            vals = [
                str(e.get("id", "")), e.get("timestamp", ""), e.get("type", ""),
                e.get("source", ""), f"{e.get('ai_confidence', 0):.2f}", e.get("details", ""),
            ]
            color = severity_color(str(e.get("type", "")))
            bad = e.get("id") in res.bad_entries
            for c, v in enumerate(vals):
                item = QTableWidgetItem(v)
                if bad:
                    item.setBackground(QBrush(QColor("#F7E7E4")))
                if color:
                    item.setForeground(QBrush(QColor(color)))
                self.table.setItem(r, c, item)
        self.table.scrollToBottom()

        n = len(res.logs)
        if res.intact:
            self.integrity_label.setText(f"Integrity: VERIFIED \u2014 {n} entries, hashes and Merkle root match")
            self.integrity_label.setStyleSheet("font-weight: 600; color: #2F7A4D;")
        else:
            parts = []
            if res.bad_entries:
                parts.append(f"entries with altered content: {res.bad_entries}")
            if not res.root_matches:
                parts.append("Merkle root does not match (entries added, removed or reordered)")
            self.integrity_label.setText("Integrity: TAMPERING DETECTED \u2014 " + "; ".join(parts))
            self.integrity_label.setStyleSheet("font-weight: 600; color: #B23A2F;")
        self.root_label.setText(f"Merkle root: {res.stored_root}")
        self._apply_filter()

    def _apply_filter(self):
        needle = self.filter_edit.text().strip().lower()
        for r in range(self.table.rowCount()):
            if not needle:
                self.table.setRowHidden(r, False)
                continue
            row_text = " ".join(
                (self.table.item(r, c).text() if self.table.item(r, c) else "")
                for c in range(self.table.columnCount())
            ).lower()
            self.table.setRowHidden(r, needle not in row_text)
