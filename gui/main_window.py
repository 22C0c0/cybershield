"""CyberShield GUI — command center window."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QMainWindow, QTabWidget

from gui.tabs.dashboard import DashboardTab
from gui.tabs.nids_tab import NidsTab
from gui.tabs.sandbox_tab import SandboxTab
from gui.tabs.secrets_tab import SecretsTab
from gui.tabs.siem_tab import SiemTab
from gui.tabs.vuln_tab import VulnTab
from gui.tabs.zero_trust_tab import ZeroTrustTab
from gui.theme import APP_STYLESHEET


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("CyberShield — Cybersecurity Utility")
        self.resize(1240, 820)
        self.setStyleSheet(APP_STYLESHEET)

        tabs = QTabWidget()
        self.dashboard_tab = DashboardTab()
        tabs.addTab(self.dashboard_tab, "Dashboard")
        tabs.addTab(NidsTab(), "NIDS")
        tabs.addTab(SandboxTab(), "Malware Sandbox")
        tabs.addTab(VulnTab(), "Vuln Scanner")
        tabs.addTab(SiemTab(), "SIEM")
        tabs.addTab(ZeroTrustTab(), "Zero Trust")
        tabs.addTab(SecretsTab(), "Secrets Detector")
        self.setCentralWidget(tabs)

        self.statusBar().showMessage("Ready — platform loaded in-process")


def main() -> int:
    from PySide6.QtWidgets import QApplication

    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
