"""
topology_widget.py -- Client -> Firewall -> Server -> MySQL diagram
(SRS 3.4). Nodes show status colours only (per stakeholder decision: no
live traffic animation). Every colour is derived from a real signal:
  - Client / Firewall / Server nodes: their ProcessController state.
  - MySQL node: the server's own startup lines (mock DB, connected,
    connection failed), because the server process can be running while
    its database is not reachable.
Nothing here is simulated or invented.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QBrush, QColor, QFont, QPainter, QPen, QPolygonF
from PySide6.QtWidgets import (
    QGraphicsPolygonItem, QGraphicsLineItem, QGraphicsRectItem, QGraphicsScene,
    QGraphicsSimpleTextItem, QGraphicsView, QLabel, QVBoxLayout, QWidget,
)

GRAY = "#8A8F98"
AMBER = "#C9A227"
GREEN = "#2F7A4D"
RED = "#B23A2F"
BLUE = "#2A5CA6"

NODE_W, NODE_H, GAP = 170, 84, 90


def process_status(state: str, awaits_ready: bool) -> tuple[str, str]:
    """Maps a ProcessController state string to (label, colour)."""
    if state == "stopped":
        return "Offline", GRAY
    if state == "starting":
        return "Starting", AMBER
    if state == "running":
        return ("Initializing", AMBER) if awaits_ready else ("Running", GREEN)
    if state == "ready":
        return "Ready", GREEN
    if state == "crashed":
        return "Crashed", RED
    return state, GRAY


# Server startup lines (server.py) -> MySQL node status. Order matters:
# the first matching marker in a chunk wins.
_DB_MARKERS = [
    ("Using sandboxed MOCK database", ("Mock DB (sandbox)", BLUE)),
    ("Connected to MySQL database", ("Connected", GREEN)),
    ("MySQL connection failed", ("Unreachable", RED)),
    ("Could not initialize mock database", ("Error", RED)),
    ("mock_mysql.py could not be imported", ("Error", RED)),
]


def db_status_from_output(text: str) -> Optional[tuple[str, str]]:
    for marker, status in _DB_MARKERS:
        if marker in text:
            return status
    return None


class NodeItem(QGraphicsRectItem):
    def __init__(self, x: float, title: str):
        super().__init__(QRectF(x, 0, NODE_W, NODE_H))
        self.setPen(QPen(QColor("#5C6270"), 1.5))
        self.setBrush(QBrush(QColor("#FFFFFF")))

        self.title = QGraphicsSimpleTextItem(title, self)
        f = QFont("Segoe UI", 11)
        f.setBold(True)
        self.title.setFont(f)
        self.title.setBrush(QBrush(QColor("#14181F")))

        self.status_text = QGraphicsSimpleTextItem("Offline", self)
        self.status_text.setFont(QFont("Segoe UI", 9))

        self.bar = QGraphicsRectItem(QRectF(x, NODE_H - 10, NODE_W, 10), self)
        self.bar.setPen(QPen(Qt.NoPen))

        self._x = x
        self.set_status("Offline", GRAY)
        self._center_text(self.title, 12)

    def _center_text(self, item: QGraphicsSimpleTextItem, y: float):
        w = item.boundingRect().width()
        item.setPos(self._x + (NODE_W - w) / 2, y)

    def set_status(self, text: str, color: str):
        self.status_text.setText(text)
        self.status_text.setBrush(QBrush(QColor(color)))
        self.bar.setBrush(QBrush(QColor(color)))
        self._center_text(self.status_text, 42)
        self.setToolTip(f"{self.title.text()}: {text}")


class EdgeItem:
    """A line with an arrow head between two adjacent nodes."""

    def __init__(self, scene: QGraphicsScene, x1: float, x2: float, y: float, label: str):
        self.line = QGraphicsLineItem(x1, y, x2 - 8, y)
        self.head = QGraphicsPolygonItem(QPolygonF([
            QPointF(x2, y), QPointF(x2 - 12, y - 6), QPointF(x2 - 12, y + 6)
        ]))
        self.label = QGraphicsSimpleTextItem(label)
        self.label.setFont(QFont("Consolas", 9))
        self.label.setBrush(QBrush(QColor("#FFFFFF")))
        lw = self.label.boundingRect().width()
        self.label.setPos((x1 + x2 - lw) / 2, y - 22)
        for it in (self.line, self.head, self.label):
            scene.addItem(it)
        self.set_active(False)

    def set_active(self, active: bool):
        color = QColor(GREEN if active else "#B8BCC4")
        self.line.setPen(QPen(color, 2.5))
        self.head.setPen(QPen(color))
        self.head.setBrush(QBrush(color))

    def set_label(self, text: str):
        self.label.setText(text)


class TopologyWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)

        self.path_label = QLabel(
            "Firewall: ENABLED   |   Connection path: Client \u2192 Firewall \u2192 Server \u2192 MySQL"
        )
        self.path_label.setAlignment(Qt.AlignCenter)
        self.path_label.setStyleSheet("font-weight: 600; color: #14181F;")
        layout.addWidget(self.path_label)

        self.scene = QGraphicsScene(self)
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(QPainter.Antialiasing)
        self.view.setFrameShape(QGraphicsView.NoFrame)
        self.view.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.view.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        layout.addWidget(self.view, 1)

        names = ["CLIENT", "FIREWALL", "SERVER", "MYSQL"]
        self.nodes: dict[str, NodeItem] = {}
        for i, name in enumerate(names):
            node = NodeItem(i * (NODE_W + GAP), name)
            self.scene.addItem(node)
            self.nodes[name] = node

        y = NODE_H / 2
        self.edges = {
            "client_fw": EdgeItem(self.scene, NODE_W, NODE_W + GAP, y, "TCP :8080"),
            "fw_server": EdgeItem(self.scene, 2 * NODE_W + GAP, 2 * (NODE_W + GAP), y, "TCP :9091"),
            "server_db": EdgeItem(self.scene, 3 * NODE_W + 2 * GAP, 3 * (NODE_W + GAP), y, "SQL"),
        }
        self.scene.setSceneRect(-20, -40, 4 * NODE_W + 3 * GAP + 40, NODE_H + 80)

        self._proc_state = {"CLIENT": ("Offline", GRAY), "FIREWALL": ("Offline", GRAY),
                            "SERVER": ("Offline", GRAY)}
        self._db_status = ("Offline", GRAY)
        self._server_running = False

    # -----------------------------------------------------------------
    def set_ports(self, firewall_port: int, backend_port: int):
        self.edges["client_fw"].set_label(f"TCP :{firewall_port}")
        self.edges["fw_server"].set_label(f"TCP :{backend_port}")

    def bind(self, name: str, controller):
        """name: 'CLIENT' | 'FIREWALL' | 'SERVER'."""
        def on_state(state: str, name=name, ctrl=controller):
            self._proc_state[name] = process_status(state, ctrl.awaits_ready)
            self.nodes[name].set_status(*self._proc_state[name])
            if name == "SERVER":
                if state in ("stopped", "crashed"):
                    self._server_running = False
                    self._db_status = ("Offline", GRAY)
                elif state == "starting":
                    self._server_running = True
                    self._db_status = ("Waiting", AMBER)
                self.nodes["MYSQL"].set_status(*self._db_status)
            self._refresh_edges()

        controller.state_changed.connect(on_state)

        if name == "SERVER":
            def on_output(text: str):
                st = db_status_from_output(text)
                if st is not None:
                    self._db_status = st
                    self.nodes["MYSQL"].set_status(*st)
                    self._refresh_edges()
            controller.output_text.connect(on_output)

    def _is_up(self, name: str) -> bool:
        return self._proc_state[name][1] == GREEN

    def _refresh_edges(self):
        self.edges["client_fw"].set_active(self._is_up("CLIENT") and self._is_up("FIREWALL"))
        self.edges["fw_server"].set_active(self._is_up("FIREWALL") and self._is_up("SERVER"))
        self.edges["server_db"].set_active(self._is_up("SERVER") and self._db_status[1] in (GREEN, BLUE))

    # -----------------------------------------------------------------
    def _fit(self):
        self.view.fitInView(self.scene.sceneRect(), Qt.KeepAspectRatio)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._fit()

    def showEvent(self, event):
        super().showEvent(event)
        self._fit()
