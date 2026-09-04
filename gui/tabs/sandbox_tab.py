"""Malware Sandbox tab — upload a file for static + dynamic analysis."""

from __future__ import annotations

import json

from PySide6.QtWidgets import (
    QCheckBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from gui.session import session
from gui.theme import banner, verdict_color
from gui.workers import Worker

_HINT = (
    "Select a file to analyze. The sandbox computes cryptographic hashes, "
    "analyzes file type and suspicious strings (static), optionally executes "
    "the file in an isolated environment (dynamic), and runs YARA rules."
)


class SandboxTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._worker: Worker | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(banner("Malware Sandbox", _HINT))

        group = QGroupBox("Analysis")
        form = QVBoxLayout(group)
        row = QHBoxLayout()
        self.file_path_edit = QLabel("No file selected")
        self.file_path_edit.setStyleSheet("color:#9aa4b2;")
        row.addWidget(self.file_path_edit, stretch=1)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse)
        self.analyze_btn = QPushButton("Analyze File")
        self.analyze_btn.clicked.connect(self._analyze)
        self.dynamic_check = QCheckBox("Run dynamic analysis (execute in sandbox)")
        self.dynamic_check.setChecked(True)
        row.addWidget(browse_btn)
        row.addWidget(self.analyze_btn)
        form.addLayout(row)
        form.addWidget(self.dynamic_check)

        result_row = QHBoxLayout()
        result_row.addWidget(QLabel("Risk score"))
        self.risk_bar = QProgressBar()
        self.risk_bar.setRange(0, 100)
        result_row.addWidget(self.risk_bar, stretch=1)
        self.verdict_label = QLabel("verdict: --")
        self.verdict_label.setObjectName("val")
        result_row.addWidget(self.verdict_label)
        form.addLayout(result_row)

        result_meta = QHBoxLayout()
        self._meta_labels: dict[str, QLabel] = {}
        for key, title in (
            ("hash", "SHA-256"),
            ("type", "Type"),
            ("size", "Size"),
            ("time", "Time"),
        ):
            box = QGroupBox(title)
            box_layout = QVBoxLayout(box)
            value = QLabel("-")
            value.setObjectName("val")
            box_layout.addWidget(value)
            result_meta.addWidget(box)
            self._meta_labels[key] = value
        form.addLayout(result_meta)

        layout.addWidget(group)

        detail_group = QGroupBox("Detailed Report (JSON)")
        detail_layout = QVBoxLayout(detail_group)
        self.report_text = QPlainTextEdit()
        self.report_text.setReadOnly(True)
        self.report_text.setStyleSheet("font-family:monospace; font-size:12px;")
        detail_layout.addWidget(self.report_text)
        layout.addWidget(detail_group, stretch=1)

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select file to analyze")
        if path:
            self.file_path_edit.setText(path)
            self._meta_labels["type"].setText("-")
            self._meta_labels["size"].setText("-")
            self._meta_labels["time"].setText("-")
            self._meta_labels["hash"].setText("-")
            self.risk_bar.setValue(0)
            self.verdict_label.setText("verdict: --")
            self.report_text.clear()

    def _analyze(self) -> None:
        from pathlib import Path

        path = Path(self.file_path_edit.text())
        if not path.is_file():
            QMessageBox.warning(self, "No file", "Choose a valid file first.")
            return
        self.analyze_btn.setEnabled(False)
        run_dynamic = self.dynamic_check.isChecked()
        self._worker = Worker(session.sandbox.analyze_file, path, run_dynamic=run_dynamic)
        self._worker.finished.connect(self._on_result)
        self._worker.failed.connect(self._on_failed)
        self._worker.start()

    def _on_result(self, result) -> None:
        self.analyze_btn.setEnabled(True)
        self._meta_labels["hash"].setText(result.file_hash.get("sha256", "-")[:48])
        self._meta_labels["type"].setText(result.file_type)
        self._meta_labels["size"].setText(f"{result.file_size:,} B")
        self._meta_labels["time"].setText(f"{result.analysis_time:.2f}s")
        self.risk_bar.setValue(round(result.risk_score * 100))
        self.verdict_label.setText(f"verdict: {result.verdict}")
        self.verdict_label.setStyleSheet(
            f"color: {verdict_color(result.verdict)}; font-weight:700;"
        )
        self._meta_labels["hash"].setToolTip(
            f"sha256\n{result.file_hash.get('sha256', '')}\n\n"
            f"md5\n{result.file_hash.get('md5', '')}\n\n"
            f"sha1\n{result.file_hash.get('sha1', '')}"
        )
        self.report_text.setPlainText(json.dumps(result.to_dict(), indent=2))

        for alert in result.alerts:
            session.sandbox_alerts.append(alert)

    def _on_failed(self, message: str) -> None:
        self.analyze_btn.setEnabled(True)
        QMessageBox.critical(self, "Analysis failed", message)
