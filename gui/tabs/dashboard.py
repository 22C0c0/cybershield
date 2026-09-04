"""Dashboard tab — live status of every module and aggregated alerts."""

from __future__ import annotations

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.session import session
from gui.theme import banner, make_table, severity_color


class DashboardTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._build_ui()
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.refresh)
        self._timer.start(2000)

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(
            banner(
                "CyberShield Command Center",
                "Living status of all six security modules. "
                "Alert aggregation across NIDS, Sandbox, SIEM and Zero-Trust.",
            )
        )

        grid = QGridLayout()
        self._module_widgets: dict[str, dict[str, QLabel]] = {}
        for col, (name, _engine) in enumerate(
            [
                ("NIDS", session.nids),
                ("Malware Sandbox", session.sandbox),
                ("Vuln Scanner", session.vuln),
                ("SIEM", session.siem),
                ("Zero Trust", session.zero_trust),
                ("Secrets", session.secrets),
            ]
        ):
            group = QGroupBox(name)
            form = QFormLayout(group)
            status = QLabel("N/A")
            status.setObjectName("statusgreen")
            rows: dict[str, QLabel] = {"status": status}
            form.addRow("Status", status)
            for key in ("pkts", "alerts", "action"):
                rows[key] = QLabel("-")
                rows[key].setObjectName("val")
                form.addRow(key, rows[key])
            self._module_widgets[name] = rows
            grid.addWidget(group, col // 3, col % 3)
        layout.addLayout(grid)

        alerts_group = QGroupBox("Global Alerts")
        alerts_layout = QVBoxLayout(alerts_group)
        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        alerts_layout.addWidget(refresh_btn, alignment=Qt.AlignmentFlag.AlignRight)
        self.alerts_table = make_table(
            ["Severity", "Module", "Title", "Source IP", "Timestamp", "Description", "ID"]
        )
        alerts_layout.addWidget(self.alerts_table)
        layout.addWidget(alerts_group, stretch=1)

        self._stats_json = QLabel("")
        self._stats_json.setWordWrap(True)
        self._stats_json.setStyleSheet("color:#9aa4b2; font-family:monospace; font-size:12px;")
        layout.addWidget(self._stats_json)

        self.refresh()

    def refresh(self) -> None:
        self._populate_modules()
        self._populate_alerts()

    def _populate_modules(self) -> None:
        nids_stats = session.nids.get_stats()
        siem_stats = session.siem.get_stats()
        zt_stats = session.zero_trust.get_stats()
        vuln_summary = session.vuln.get_summary()
        secret_report = session.secrets.generate_report()

        rows = {
            "NIDS": {
                "pkts": str(nids_stats["total_packets"]),
                "alerts": str(nids_stats["alerts_generated"]),
                "action": "capture off",
            },
            "Malware Sandbox": {
                "pkts": f"{len(session.sandbox_alerts)} alerts",
                "alerts": str(len(session.sandbox_alerts)),
                "action": f"{secret_report.get('files_scanned', 0)} sc",  # placeholder
            },
            "Vuln Scanner": {
                "pkts": f"{vuln_summary.get('hosts_scanned', 0)} hosts",
                "alerts": str(vuln_summary.get("alerts_generated", 0)),
                "action": f"{vuln_summary.get('open_ports', 0)} open",
            },
            "SIEM": {
                "pkts": f"{siem_stats['logs_processed']} logs",
                "alerts": str(siem_stats["alerts"]["total_alerts"]),
                "action": f"{siem_stats['active_rules']} rules",
            },
            "Zero Trust": {
                "pkts": f"{zt_stats['total_users']} users",
                "alerts": str(zt_stats["alerts"]),
                "action": f"{zt_stats['active_sessions']} sessions",
            },
            "Secrets": {
                "pkts": f"{secret_report['files_scanned']} files",
                "alerts": str(secret_report["total_findings"]),
                "action": "scanner",
            },
        }
        for name, values in rows.items():
            for key, label in self._module_widgets[name].items():
                if key == "status":
                    label.setText("READY")
                    continue
                label.setText(values.get(key, "-"))

        self._stats_json.setText(
            f"NIDS n/a | SIEM logs: {siem_stats['logs_processed']} | "
            f"ZT users: {zt_stats['total_users']} | "
            f"Secrets findings: {secret_report['total_findings']}"
        )

    def _populate_alerts(self) -> None:
        alerts = session.all_alerts()[:200]
        self.alerts_table.setRowCount(len(alerts))
        for row, alert in enumerate(alerts):
            sev = alert.get("severity", "info")
            color = severity_color(sev)
            items = (
                sev,
                alert.get("module", ""),
                alert.get("title", ""),
                alert.get("source_ip", ""),
                alert.get("timestamp", "")[:19],
                alert.get("description", ""),
                alert.get("id", "")[:8],
            )
            for col, text in enumerate(items):
                cell = QLabel(str(text))
                if col == 0:
                    cell.setStyleSheet(f"color:{color}; font-weight:700;")
                cell.setWordWrap(True)
                self.alerts_table.setCellWidget(row, col, cell)
        header = self.alerts_table.horizontalHeader()
        header.setSectionResizeMode(5, header.ResizeMode.Stretch)
        self.alerts_table.resizeRowsToContents()
