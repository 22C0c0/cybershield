"""SIEM tab — log ingestion, detection rules and alert correlation."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui.session import session
from gui.theme import banner, make_table, severity_color
from gui.workers import Worker

_SAMPLE_LOGS = (
    "Failed password for root from 192.168.1.100 port 22 ssh2\n"
    "Accepted publickey for admin from 10.0.0.5 port 443 ssh2\n"
    "sudo: user : command not allowed ; USER=root ; COMMAND=/bin/cat /etc/shadow\n"
    "kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.0.1 DST=10.0.0.1\n"
)


class SiemTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._worker: Worker | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(
            banner(
                "Security Information & Event Management",
                "Parse syslog, apache and auth log lines; detect brute-force SSH, "
                "privilege escalation, firewall blocks and more.",
            )
        )

        input_group = QGroupBox("Log ingestion")
        input_layout = QVBoxLayout(input_group)
        self.log_text = QPlainTextEdit()
        self.log_text.setPlaceholderText("Paste log lines here, one per line...")
        self.log_text.setPlainText(_SAMPLE_LOGS)
        input_layout.addWidget(self.log_text)

        row = QHBoxLayout()
        ingest_btn = QPushButton("Ingest Logs")
        ingest_btn.clicked.connect(self._ingest)
        load_btn = QPushButton("Load log file...")
        load_btn.clicked.connect(self._load_file)
        sample_btn = QPushButton("Load sample")
        sample_btn.clicked.connect(lambda: self.log_text.setPlainText(_SAMPLE_LOGS))
        row.addWidget(ingest_btn)
        row.addWidget(load_btn)
        row.addWidget(sample_btn)
        self.stats_label = QLabel("logs: 0 | alerts: 0 | rules: 0")
        self.stats_label.setStyleSheet("color:#9aa4b2;")
        row.addWidget(self.stats_label, stretch=1)
        input_layout.addLayout(row)
        layout.addWidget(input_group)

        alert_group = QGroupBox("Generated alerts")
        alert_layout = QVBoxLayout(alert_group)
        self.alerts_table = make_table(
            ["Severity", "Title", "Source", "Ip/Source", "Description", "Tags"]
        )
        alert_layout.addWidget(self.alerts_table)
        layout.addWidget(alert_group, stretch=1)

        self._refresh_alerts()
        self._refresh_stats()

    def _ingest(self) -> None:
        lines = self.log_text.toPlainText().splitlines()
        if not any(line.strip() for line in lines):
            return

        def _run() -> list[dict]:
            alerts = session.siem.ingest_batch(lines, source="gui")
            return [a.to_dict() for a in alerts]

        self._worker = Worker(_run)
        self._worker.finished.connect(lambda _: (self._refresh_stats(), self._refresh_alerts()))
        self._worker.failed.connect(lambda msg: QMessageBox.critical(self, "Ingest failed", msg))
        self._worker.start()

    def _load_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select log file")
        if not path:
            return
        self._worker = Worker(session.siem.ingest_file, Path(path))
        self._worker.finished.connect(lambda _: (self._refresh_stats(), self._refresh_alerts()))
        self._worker.failed.connect(lambda msg: QMessageBox.critical(self, "Ingest failed", msg))
        self._worker.start()

    def _refresh_stats(self) -> None:
        stats = session.siem.get_stats()
        self.stats_label.setText(
            f"logs: {stats['logs_processed']} | "
            f"alerts: {stats['alerts']['total_alerts']} | rules: {stats['active_rules']}"
        )

    def _refresh_alerts(self) -> None:
        alerts = [a.to_dict() for a in session.siem.alert_store.get_alerts(limit=200)]
        self.alerts_table.setRowCount(len(alerts))
        for row, alert in enumerate(alerts):
            sev = alert.get("severity", "info")
            values = (
                sev,
                alert.get("title", ""),
                alert.get("metadata", {}).get("source_ip", alert.get("source_ip", "")),
                alert.get("source_ip", ""),
                alert.get("description", ""),
                ", ".join(alert.get("tags", [])),
            )
            for col, text in enumerate(values):
                item = QTableWidgetItem(str(text))
                if col == 0:
                    item.setForeground(QColor(severity_color(sev)))
                self.alerts_table.setItem(row, col, item)
        header = self.alerts_table.horizontalHeader()
        header.setSectionResizeMode(4, header.ResizeMode.Stretch)
        self.alerts_table.resizeRowsToContents()
