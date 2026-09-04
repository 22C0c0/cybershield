"""NIDS tab — packet capture control, live stats, signatures and alerts."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui.platform import detect_interface, platform_name, requires_admin_hint
from gui.session import session
from gui.theme import banner, make_table, severity_color
from gui.workers import CaptureWorker


class NidsTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._worker: CaptureWorker | None = None
        self._build_ui()
        self._refresh_stats()
        self._refresh_signatures()

        self._stats_timer = QTimer(self)
        self._stats_timer.timeout.connect(self._refresh_stats)
        self._stats_timer.setInterval(1500)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(
            banner(
                "Network Intrusion Detection",
                "Live packet capture with signature matching (SQLi, XSS, reverse shells) "
                "and anomaly detection (SYN flood, port scan). " + requires_admin_hint(),
            )
        )

        controls = QGroupBox("Capture")
        ctrl_layout = QVBoxLayout(controls)
        row = QHBoxLayout()
        row.addWidget(QLabel("Interface"))
        self.interface_edit = QLineEdit(detect_interface())
        self.interface_edit.setPlaceholderText("e.g. eth0, en0, wlan0, ethernet")
        row.addWidget(self.interface_edit, stretch=1)
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.clicked.connect(self._start)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        row.addWidget(self.start_btn)
        row.addWidget(self.stop_btn)
        ctrl_layout.addLayout(row)

        stats_row = QHBoxLayout()
        self._stats_labels: dict[str, QLabel] = {}
        for key, title in (
            ("total", "Total packets"),
            ("tcp", "TCP"),
            ("udp", "UDP"),
            ("icmp", "ICMP"),
            ("suspicious", "Suspicious"),
            ("bytes", "Bytes"),
            ("alerts", "Alerts"),
        ):
            box = QGroupBox(title)
            box_layout = QVBoxLayout(box)
            value = QLabel("0")
            value.setObjectName("val")
            value.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._stats_labels[key] = value
            box_layout.addWidget(value)
            stats_row.addWidget(box)
        ctrl_layout.addLayout(stats_row)
        layout.addWidget(controls)

        sig_group = QGroupBox("Signatures")
        sig_layout = QVBoxLayout(sig_group)
        sig_refresh = QPushButton("List Signatures")
        sig_refresh.clicked.connect(self._refresh_signatures)
        sig_layout.addWidget(sig_refresh, alignment=Qt.AlignmentFlag.AlignLeft)
        self.signatures_table = make_table(["Name", "Pattern", "Severity", "Tags"])
        sig_layout.addWidget(self.signatures_table)
        layout.addWidget(sig_group, stretch=1)

        alert_group = QGroupBox("Alerts")
        alert_layout = QVBoxLayout(alert_group)
        self.alerts_table = make_table(
            ["Severity", "Title", "Source", "Destination", "Tags", "Description"]
        )
        alert_layout.addWidget(self.alerts_table)
        layout.addWidget(alert_group, stretch=1)

    def _start(self) -> None:
        interface = self.interface_edit.text().strip() or detect_interface()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self._worker = CaptureWorker(session.nids, interface)
        self._worker.finished.connect(self._on_capture_done)
        self._worker.failed.connect(self._on_capture_failed)
        self._stats_timer.start()
        self._worker.start()

    def _stop(self) -> None:
        if self._worker:
            self._worker.stop()

    def _on_capture_done(self, _alerts: list) -> None:
        self._stop_ui()

    def _on_capture_failed(self, message: str) -> None:
        self._stop_ui()
        QMessageBox.warning(
            self,
            "Capture error",
            f"Could not start packet capture.\n\n{message}\n\n"
            f"On {platform_name()}: {requires_admin_hint()} "
            "Use an interface from `ip link` / `ifconfig` / `ipconfig`.",
        )

    def _stop_ui(self) -> None:
        self._stats_timer.stop()
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._worker = None
        self._refresh_alerts()

    def _refresh_stats(self) -> None:
        stats = session.nids.get_stats()
        mapping = {
            "total": stats["total_packets"],
            "tcp": stats["tcp_packets"],
            "udp": stats["udp_packets"],
            "icmp": stats["icmp_packets"],
            "suspicious": stats["suspicious_packets"],
            "bytes": stats["bytes_captured"],
            "alerts": stats["alerts_generated"],
        }
        for key, value in mapping.items():
            self._stats_labels[key].setText(str(value))
        self._refresh_alerts()

    def _refresh_alerts(self) -> None:
        alerts = [a.to_dict() for a in session.nids.alerts]
        self.alerts_table.setRowCount(len(alerts))
        for row, alert in enumerate(alerts):
            values = (
                alert.get("severity", ""),
                alert.get("title", ""),
                alert.get("source_ip", ""),
                alert.get("destination_ip", ""),
                ", ".join(alert.get("tags", [])),
                alert.get("description", ""),
            )
            for col, text in enumerate(values):
                item = QTableWidgetItem(str(text))
                if col == 0:
                    colour = severity_color(text)
                    item.setForeground(QColor(colour))
                self.alerts_table.setItem(row, col, item)
        header = self.alerts_table.horizontalHeader()
        header.setSectionResizeMode(5, header.ResizeMode.Stretch)
        self.alerts_table.resizeRowsToContents()

    def _refresh_signatures(self) -> None:
        signatures = session.nids.signature_engine.signatures
        self.signatures_table.setRowCount(len(signatures))
        for row, sig in enumerate(signatures):
            values = (
                sig.name,
                sig.pattern.decode("utf-8", errors="replace"),
                sig.severity.value,
                ", ".join(sig.tags),
            )
            for col, text in enumerate(values):
                item = QTableWidgetItem(str(text))
                self.signatures_table.setItem(row, col, item)
        self.signatures_table.resizeRowsToContents()
        self.signatures_table.setColumnWidth(1, 480)
