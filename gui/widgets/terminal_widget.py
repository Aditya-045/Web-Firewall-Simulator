"""
terminal_widget.py -- one dock's worth of UI: a read-only output pane fed
by a ProcessController's output_text signal, plus (for the two
interactive processes) a one-line input box wired to write_line().

Increment 2 additions (SRS 3.5 / 4):
  - Display-only colour tagging of lines (never alters what the backend
    decided; it only recolours text already received).
  - Password-aware input: when the child's most recent prompt mentions
    "password", the input box switches to masked entry and the local echo
    line shows ******** instead of the typed text, so the secret never
    enters the terminal document and therefore never reaches an export.
  - Export Log (per terminal), with a defensive redaction pass.
"""

from __future__ import annotations

import re
from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QSyntaxHighlighter, QTextCharFormat, QTextCursor
from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
    QPushButton, QVBoxLayout, QWidget,
)

STATE_COLORS = {
    "stopped": "#8A8F98",
    "starting": "#C9A227",
    "running": "#C9A227",
    "ready": "#2F7A4D",
    "crashed": "#B23A2F",
}

MASK = "********"

# Defensive export-time redaction for wire-format credential strings
# (REGISTER:user:pass, LOGIN:user:pass, ADMIN_LOGIN:user:pass). The
# backend never prints these, and typed passwords are already masked at
# echo time, so this is a second layer, not the primary control.
_CRED_RE = re.compile(r"\b(REGISTER|LOGIN|ADMIN_LOGIN):([^:\s]+):\S+")


def redact(text: str) -> str:
    return _CRED_RE.sub(lambda m: f"{m.group(1)}:{m.group(2)}:{MASK}", text)


# ---------------------------------------------------------------------
# Colour tagging (display only). Priority: red > amber > green.
# Uppercase tokens are matched case-sensitively on purpose so ordinary
# prose such as "shouldn't be allowed" or "No warnings" is not recoloured.
# ---------------------------------------------------------------------
_RED = re.compile(
    r"BLOCKED|DENIED|REJECTED|ERROR|Terminated|CRASH|"
    r"(?i:failed|refused|invalid username|locked until|too many failed)"
)
_AMBER = re.compile(r"WARNING|Orange|Cautioned|\[!\]")
_GREEN = re.compile(r"ALLOWED|GRANTED|Granted|Login successful|Registered\.|Green \(0/2\)")

_FMT_RED = QTextCharFormat()
_FMT_RED.setForeground(QColor("#B23A2F"))
_FMT_AMBER = QTextCharFormat()
_FMT_AMBER.setForeground(QColor("#B7791F"))
_FMT_GREEN = QTextCharFormat()
_FMT_GREEN.setForeground(QColor("#2F7A4D"))


def classify_line(line: str) -> Optional[str]:
    """Returns 'red' | 'amber' | 'green' | None. Exposed for tests."""
    if _RED.search(line):
        return "red"
    if _AMBER.search(line):
        return "amber"
    if _GREEN.search(line):
        return "green"
    return None


class LogHighlighter(QSyntaxHighlighter):
    def highlightBlock(self, text: str):
        kind = classify_line(text)
        fmt = {"red": _FMT_RED, "amber": _FMT_AMBER, "green": _FMT_GREEN}.get(kind)
        if fmt is not None:
            self.setFormat(0, len(text), fmt)


class TerminalWidget(QWidget):
    def __init__(self, title: str, interactive: bool, controller, parent=None):
        super().__init__(parent)
        self.controller = controller
        self.title = title
        self._tail = ""        # text after the last newline = the current prompt

        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)

        header = QHBoxLayout()
        self.title_label = QLabel("Status:")
        self.title_label.setStyleSheet("color: #5C6270;")
        self.state_label = QLabel("stopped")
        self.state_label.setStyleSheet(f"color: {STATE_COLORS['stopped']}; font-family: monospace;")
        header.addWidget(self.title_label)
        header.addWidget(self.state_label)
        header.addStretch(1)
        layout.addLayout(header)

        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        self.output.setMaximumBlockCount(5000)
        self.output.setFont(QFont("Consolas", 9))
        self._highlighter = LogHighlighter(self.output.document())
        layout.addWidget(self.output, 1)

        btn_row = QHBoxLayout()
        clear_btn = QPushButton("Clear")
        clear_btn.clicked.connect(self.clear)
        export_btn = QPushButton("Export Log...")
        export_btn.clicked.connect(self.export_dialog)
        btn_row.addWidget(clear_btn)
        btn_row.addWidget(export_btn)
        btn_row.addStretch(1)
        layout.addLayout(btn_row)

        self.input_box: Optional[QLineEdit] = None
        if interactive:
            input_row = QHBoxLayout()
            self.input_box = QLineEdit()
            self.input_box.setPlaceholderText("Type a menu choice / answer, press Enter...")
            self.input_box.returnPressed.connect(self._on_enter)
            send_btn = QPushButton("Send")
            send_btn.clicked.connect(self._on_enter)
            input_row.addWidget(self.input_box, 1)
            input_row.addWidget(send_btn)
            layout.addLayout(input_row)

        controller.output_text.connect(self._append_text)
        controller.state_changed.connect(self._on_state_changed)
        controller.error_occurred.connect(lambda msg: self._append_text(f"\n[LAUNCH ERROR] {msg}\n"))

    # -----------------------------------------------------------------
    # Prompt / masking
    # -----------------------------------------------------------------
    def prompt_wants_secret(self) -> bool:
        return "password" in self._tail.lower()

    def _refresh_mask(self):
        if self.input_box is None:
            return
        mode = QLineEdit.Password if self.prompt_wants_secret() else QLineEdit.Normal
        if self.input_box.echoMode() != mode:
            self.input_box.setEchoMode(mode)

    def _on_enter(self):
        if self.input_box is None:
            return
        text = self.input_box.text()
        secret = self.prompt_wants_secret()
        self.input_box.clear()
        # Echo locally, since the child doesn't echo piped stdin itself. A
        # secret is never written into the document, so it can't be
        # exported or copied out of the terminal pane.
        self._append_text(f"\n> {MASK if secret else text}\n", from_user=True)
        self.controller.write_line(text)

    # -----------------------------------------------------------------
    def _append_text(self, text: str, from_user: bool = False):
        cursor = self.output.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.output.setTextCursor(cursor)
        self.output.insertPlainText(text)
        self.output.verticalScrollBar().setValue(self.output.verticalScrollBar().maximum())

        if "\n" in text:
            self._tail = text.rsplit("\n", 1)[1]
        else:
            self._tail = (self._tail + text)[-300:]
        self._refresh_mask()

    def _on_state_changed(self, state: str):
        color = STATE_COLORS.get(state, "#8A8F98")
        if state == "running" and not self.controller.awaits_ready:
            color = STATE_COLORS["ready"]   # no separate ready stage: running IS healthy
        self.state_label.setText(state)
        self.state_label.setStyleSheet(f"color: {color}; font-family: monospace; font-weight: 600;")
        if self.input_box is not None:
            self.input_box.setEnabled(state == "running")
            if state in ("stopped", "crashed"):
                self._tail = ""
                self._refresh_mask()

    def echo_sent(self, text: str):
        """Shows a command the GUI itself wrote to the child's stdin (e.g.
        the periodic admin 'status' refresh), so nothing is ever sent to a
        process without being visible in its terminal."""
        self._append_text(f"\n> {text}   (sent by GUI)\n", from_user=True)

    # -----------------------------------------------------------------
    # Clear / export
    # -----------------------------------------------------------------
    def clear(self):
        self.output.clear()
        self._tail = ""
        self._refresh_mask()

    def export_text(self) -> str:
        return redact(self.output.toPlainText())

    def export_dialog(self):
        path, _ = QFileDialog.getSaveFileName(
            self, f"Export {self.title}", f"{self.title.replace(' ', '_').lower()}.log",
            "Log files (*.log *.txt);;All files (*)",
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.export_text())
        except OSError as e:
            QMessageBox.critical(self, "Export failed", str(e))
