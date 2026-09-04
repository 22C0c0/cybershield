"""Vulnerability Scanner tab — host and network port scanning with CVE matching."""

from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui.session import session
from gui.theme import banner, make_table
from gui.workers import AsyncWorker


class VulnTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._worker: AsyncWorker | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(
            banner(
                "Vulnerability Scanner",
                "Fast async TCP scanning with banner grabbing, service identification, "
                "and CVE correlation (Log4Shell, Rapid Reset, PrintNightmare, ...).",
            )
        )

        controls = QGroupBox("Scan target")
        row = QHBoxLayout()
        row.addWidget(QLabel("Host / CIDR"))
        self.target_edit = QLineEdit("127.0.0.1")
        self.target_edit.setPlaceholderText("e.g. 192.168.1.10 or 192.168.1.0/24")
        row.addWidget(self.target_edit, stretch=1)
        self.network_check = QCheckBox("Network scan (CIDR)")
        row.addWidget(self.network_check)
        self.scan_btn = QPushButton("Start Scan")
        self.scan_btn.clicked.connect(self._scan)
        row.addWidget(self.scan_btn)
        controls_layout = QVBoxLayout(controls)
        controls_layout.addLayout(row)
        self.status_label = QLabel("")
        self.status_label.setStyleSheet("color:#9aa4b2;")
        controls_layout.addWidget(self.status_label)
        layout.addWidget(controls)

        hosts_group = QGroupBox("Hosts")
        hosts_layout = QVBoxLayout(hosts_group)
        self.hosts_table = make_table(["IP", "Hostname", "OS", "Open ports", "Vulns", "Scan time"])
        hosts_layout.addWidget(self.hosts_table)
        layout.addWidget(hosts_group, stretch=1)

        detail_group = QGroupBox("Vulnerabilities")
        detail_layout = QVBoxLayout(detail_group)
        self.vulns_text = QPlainTextEdit()
        self.vulns_text.setReadOnly(True)
        self.vulns_text.setStyleSheet("font-family:monospace; font-size:12px;")
        detail_layout.addWidget(self.vulns_text)
        layout.addWidget(detail_group, stretch=1)

    def _scan(self) -> None:

        self.scan_btn.setEnabled(False)
        self.status_label.setText("Scanning...")
        target = self.target_edit.text().strip()
        network = self.network_check.isChecked()

        async def _run() -> list[dict]:
            if network:
                hosts = await session.vuln.scan_network(target)
            else:
                host = await session.vuln.scan_host(target)
                hosts = [host]
            return [h.to_dict() for h in hosts]

        self._worker = AsyncWorker(_run)
        self._worker.finished.connect(self._on_done)
        self._worker.failed.connect(lambda msg: self._on_failed(msg))
        self._worker.start()

    def _on_done(self, hosts: list[dict]) -> None:
        self.scan_btn.setEnabled(True)
        self.status_label.setText(f"Scan complete: {len(hosts)} host(s).")
        self.hosts_table.setRowCount(len(hosts))
        vuln_sections: list[str] = []
        for row, host in enumerate(hosts):
            values = (
                host.get("ip", ""),
                host.get("hostname", ""),
                host.get("os_guess", ""),
                str(host.get("open_ports", 0)),
                str(len(host.get("vulnerabilities", []))),
                f"{host.get('scan_time', 0):.2f}s",
            )
            for col, text in enumerate(values):
                self.hosts_table.setItem(row, col, QTableWidgetItem(str(text)))
            vulns = host.get("vulnerabilities", [])
            if vulns:
                lines = [f"=== {host.get('ip')} ==="]
                for v in vulns:
                    lines.append(
                        f"[{v.get('cve_id', '')}] {v.get('name', '')} "
                        f"({v.get('severity', '')}) - {v.get('description', '')}"
                    )
                vuln_sections.append("\n".join(lines))
            ports = host.get("ports", [])
            open_ports = [p for p in ports if p.get("state") == "open"]
            if open_ports:
                lines = [f"--- {host.get('ip')} open ports ---"]
                for p in open_ports:
                    banner_txt = (p.get("banner") or "").replace("\n", " ")[:60]
                    lines.append(
                        f"  {p.get('port'):6d}  {p.get('state'):9s} "
                        f"{p.get('service', '?'):12s} {p.get('version', ''):20s} {banner_txt}"
                    )
                vuln_sections.append("\n".join(lines))
        self.vulns_text.setPlainText("\n\n".join(vuln_sections) or "No vulnerabilities found.")

    def _on_failed(self, message: str) -> None:
        self.scan_btn.setEnabled(True)
        self.status_label.setText("")
        QMessageBox.critical(self, "Scan failed", message)

    def refresh_alerts(self) -> None:
        pass
