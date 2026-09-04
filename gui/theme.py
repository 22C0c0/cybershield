"""Shared styling and small convenience widgets for the CyberShield GUI."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QLabel, QTableWidget, QVBoxLayout, QWidget


def severity_color(severity: str) -> str:
    return {
        "critical": "#e74c3c",
        "high": "#e67e22",
        "medium": "#f1c40f",
        "low": "#3498db",
        "info": "#95a5a6",
    }.get(severity, "#95a5a6")


def verdict_color(verdict: str) -> str:
    return {
        "malicious": "#e74c3c",
        "suspicious": "#e67e22",
        "potentially_unwanted": "#f1c40f",
        "clean": "#2ecc71",
        "unknown": "#95a5a6",
    }.get(verdict, "#95a5a6")


def make_table(headers: list[str]) -> QTableWidget:
    table = QTableWidget(0, len(headers))
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().setVisible(False)
    table.setAlternatingRowColors(True)
    table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    table.horizontalHeader().setStretchLastSection(True)
    table.setStyleSheet(
        "QTableWidget::item { padding: 4px; } QTableWidget { gridline-color: #3a3f4b; }"
    )
    return table


def banner(text: str, subtitle: str = "") -> QWidget:
    widget = QWidget()
    label = QLabel(text)
    label.setStyleSheet("font-size: 20px; font-weight: 700; color: #e8eaf0; padding: 2px;")
    label.setAlignment(Qt.AlignmentFlag.AlignLeft)
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 8)
    layout.addWidget(label)
    if subtitle:
        sub = QLabel(subtitle)
        sub.setStyleSheet("font-size: 12px; color: #9aa4b2;")
        sub.setWordWrap(True)
        layout.addWidget(sub)
    return widget


APP_STYLESHEET = """
QMainWindow, QWidget { background-color: #1e222a; color: #d7dce4; font-size: 13px; }
QTabWidget::pane { border: 1px solid #3a3f4b; border-radius: 4px; }
QTabBar::tab { background: #262b34; padding: 8px 16px; margin-right: 2px;
               border-top-left-radius: 4px; border-top-right-radius: 4px; }
QTabBar::tab:selected { background: #313845; color: #7fd0ff; }
QPushButton { background: #313845; border: 1px solid #46506a; border-radius: 4px;
              padding: 6px 14px; }
QPushButton:hover { background: #3a4352; }
QPushButton:pressed { background: #262b34; }
QPushButton:disabled { color: #6b7480; background: #2a2f38; }
QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QComboBox {
    background: #14171c; border: 1px solid #3a3f4b; border-radius: 4px; padding: 5px; }
QProgressBar { border: 1px solid #3a3f4b; border-radius: 4px; text-align: center;
               background: #14171c; }
QProgressBar::chunk { background: #2e86de; border-radius: 3px; }
QGroupBox { border: 1px solid #3a3f4b; border-radius: 6px; margin-top: 10px;
            font-weight: 600; color: #9fd8ff; }
QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }
QHeaderView::section { background: #262b34; color: #c6cede; border: 1px solid #3a3f4b;
                       padding: 5px; }
QTableWidget { background: #14171c; color: #d7dce4; }
QLabel#val { color: #7fd0ff; font-weight: 600; font-size: 15px; }
QLabel#statlabel { color: #9aa4b2; font-size: 12px; }
QLabel#statusgreen { color: #2ecc71; font-weight: 700; }
QLabel#statusred { color: #e74c3c; font-weight: 700; }
QStatusBar { background: #262b34; color: #9aa4b2; }
QMessageBox QLabel { color: #d7dce4; }
"""
