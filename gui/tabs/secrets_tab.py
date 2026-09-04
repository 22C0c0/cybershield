"""Secrets Detector tab — scan files, folders, git repos or raw content for secrets."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
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


class SecretsTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._worker: Worker | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(
            banner(
                "Secrets Detector",
                "Detect AWS keys, GitHub/GitLab tokens, Slack webhooks, DB connection "
                "strings, JWTs, private keys and high-entropy secrets (17 patterns).",
            )
        )

        scan_group = QGroupBox("Scan")
        scan_layout = QVBoxLayout(scan_group)

        row = QHBoxLayout()
        self.path_edit = QLabel("No path selected")
        self.path_edit.setStyleSheet("color:#9aa4b2;")
        row.addWidget(self.path_edit, stretch=1)
        file_btn = QPushButton("Scan file")
        file_btn.clicked.connect(self._scan_file)
        dir_btn = QPushButton("Scan folder...")
        dir_btn.clicked.connect(self._scan_dir)
        git_btn = QPushButton("Scan git repo...")
        git_btn.clicked.connect(self._scan_git)
        row.addWidget(file_btn)
        row.addWidget(dir_btn)
        row.addWidget(git_btn)
        scan_layout.addLayout(row)

        self.report_label = QLabel("")
        self.report_label.setStyleSheet("color:#9aa4b2;")
        scan_layout.addWidget(self.report_label)
        layout.addWidget(scan_group)

        content_group = QGroupBox("Scan inline content")
        content_layout = QVBoxLayout(content_group)
        self.content_edit = QPlainTextEdit()
        self.content_edit.setPlaceholderText(
            "Paste content to scan, e.g.\nAPI_KEY = 'AKIAIOSFODNN7EXAMPLE'"
        )
        self.content_edit.setFixedHeight(90)
        content_layout.addWidget(self.content_edit)
        content_btn = QPushButton("Scan content")
        content_btn.clicked.connect(self._scan_content)
        content_layout.addWidget(content_btn, alignment=Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(content_group)

        findings_group = QGroupBox("Findings")
        findings_layout = QVBoxLayout(findings_group)
        self.findings_table = make_table(
            ["Severity", "Pattern", "File", "Line", "Entropy", "Matched", "Description"]
        )
        findings_layout.addWidget(self.findings_table)
        layout.addWidget(findings_group, stretch=1)

    def _scan_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select file to scan")
        if not path:
            return
        self.path_edit.setText(path)
        self._run_scan(session.secrets.scan_file, Path(path))

    def _scan_dir(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select folder to scan")
        if not path:
            return
        self.path_edit.setText(path)
        self._run_scan(session.secrets.scan_directory, Path(path))

    def _scan_git(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Select git repository")
        if not path:
            return
        self.path_edit.setText(path)
        self._run_scan(session.secrets.scan_git_repo, Path(path))

    def _scan_content(self) -> None:
        content = self.content_edit.toPlainText()
        if not content.strip():
            QMessageBox.warning(self, "Empty", "Paste some content first.")
            return
        self.path_edit.setText("inline content")
        self._run_scan(session.secrets.scan_content, content, "inline")

    def _run_scan(self, fn, *args) -> None:
        self._worker = Worker(fn, *args)
        self._worker.finished.connect(self._on_done)
        self._worker.failed.connect(lambda msg: QMessageBox.critical(self, "Scan failed", msg))
        self._worker.start()

    def _on_done(self, _findings: list) -> None:
        report = session.secrets.generate_report()
        by_sev = ", ".join(f"{k}: {v}" for k, v in report["by_severity"].items())
        self.report_label.setText(
            f"Findings: {report['total_findings']} | Files scanned: {report['files_scanned']} "
            f"| {by_sev}"
        )

        findings = list(session.secrets.findings)
        self.findings_table.setRowCount(len(findings))
        for row, f in enumerate(findings):
            sev = f.severity.value
            values = (
                sev,
                f.pattern_name,
                f.file_path,
                str(f.line_number),
                f"{f.entropy:.2f}",
                f.matched_text[:60],
                f.description,
            )
            for col, text in enumerate(values):
                item = QTableWidgetItem(str(text))
                if col == 0:
                    item.setForeground(QColor(severity_color(sev)))
                self.findings_table.setItem(row, col, item)
        header = self.findings_table.horizontalHeader()
        header.setSectionResizeMode(5, header.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(6, header.ResizeMode.Stretch)
        self.findings_table.resizeRowsToContents()
