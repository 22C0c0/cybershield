"""Zero Trust Auth Proxy tab — user management, token auth and audit trail."""

from __future__ import annotations

from PySide6.QtCore import Qt
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

from gui.session import session
from gui.theme import banner, make_table
from gui.workers import Worker


class ZeroTrustTab(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self._token: str = ""
        self._worker: Worker | None = None
        self._build_ui()
        self._refresh_audit()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.addWidget(
            banner(
                "Zero Trust Auth Proxy",
                "PBKDF2 password hashing, TOTP-style MFA, role-based access policies "
                "with lockout after repeated failures, and a full audit trail. "
                "Default account: admin / admin123.",
            )
        )

        auth_group = QGroupBox("Authentication")
        auth_layout = QHBoxLayout(auth_group)

        reg_box = QGroupBox("Register user")
        reg_layout = QHBoxLayout(reg_box)
        self.reg_user = QLineEdit()
        self.reg_user.setPlaceholderText("username")
        self.reg_pass = QLineEdit()
        self.reg_pass.setPlaceholderText("password")
        self.reg_pass.setEchoMode(QLineEdit.EchoMode.Password)
        reg_btn = QPushButton("Register")
        reg_btn.clicked.connect(self._register)
        reg_layout.addWidget(self.reg_user)
        reg_layout.addWidget(self.reg_pass)
        reg_layout.addWidget(reg_btn)
        auth_layout.addWidget(reg_box)

        login_box = QGroupBox("Login")
        login_layout = QHBoxLayout(login_box)
        self.login_user = QLineEdit()
        self.login_user.setPlaceholderText("username")
        self.login_pass = QLineEdit()
        self.login_pass.setPlaceholderText("password")
        self.login_pass.setEchoMode(QLineEdit.EchoMode.Password)
        login_btn = QPushButton("Login")
        login_btn.clicked.connect(self._login)
        logout_btn = QPushButton("Logout")
        logout_btn.clicked.connect(self._logout)
        login_layout.addWidget(self.login_user)
        login_layout.addWidget(self.login_pass)
        login_layout.addWidget(login_btn)
        login_layout.addWidget(logout_btn)
        auth_layout.addWidget(login_box, stretch=1)
        layout.addWidget(auth_group)

        token_row = QHBoxLayout()
        self.token_label = QLabel("no session")
        self.token_label.setObjectName("val")
        self.token_label.setWordWrap(True)
        token_row.addWidget(self.token_label, stretch=1)
        layout.addLayout(token_row)

        zb_group = QGroupBox("Authorization check")
        zb_layout = QHBoxLayout(zb_group)
        self.path_edit = QLineEdit("/api/v1/admin/settings")
        self.path_edit.setPlaceholderText("path to check access for")
        authz_btn = QPushButton("Check Access")
        authz_btn.clicked.connect(self._authorize)
        zb_layout.addWidget(self.path_edit, stretch=1)
        zb_layout.addWidget(authz_btn)
        self.authz_result = QLabel("")
        self.authz_result.setObjectName("val")
        zb_layout.addWidget(self.authz_result)
        layout.addWidget(zb_group)

        audit_group = QGroupBox("Audit trail")
        audit_layout = QVBoxLayout(audit_group)
        refresh_btn = QPushButton("Refresh audit")
        refresh_btn.clicked.connect(self._refresh_audit)
        audit_layout.addWidget(refresh_btn, alignment=Qt.AlignmentFlag.AlignRight)
        self.audit_table = make_table(["Time", "User", "Action", "IP", "Success", "Details"])
        audit_layout.addWidget(self.audit_table)
        layout.addWidget(audit_group, stretch=1)

    def _register(self) -> None:
        def _run() -> str:
            user = session.zero_trust.register_user(
                self.reg_user.text().strip(),
                self.reg_pass.text(),
            )
            return f"Registered user '{user.username}'" if user else "User already exists"

        self._worker = Worker(_run)
        self._worker.finished.connect(
            lambda msg: (QMessageBox.information(self, "Register", msg), self._refresh_audit())
        )
        self._worker.failed.connect(lambda msg: QMessageBox.critical(self, "Error", msg))
        self._worker.start()

    def _login(self) -> None:
        def _run() -> str:
            ok, token = session.zero_trust.authenticate(
                self.login_user.text().strip(),
                self.login_pass.text(),
                ip_address="127.0.0.1",
            )
            return token if ok else ""

        def _on_done(token: str) -> None:
            if not token:
                QMessageBox.warning(self, "Login failed", "Invalid credentials.")
                return
            self._token = token
            self.token_label.setText(f"session token: {token[:32]}...")
            self._refresh_audit()

        self._worker = Worker(_run)
        self._worker.finished.connect(_on_done)
        self._worker.failed.connect(lambda msg: QMessageBox.critical(self, "Error", msg))
        self._worker.start()

    def _logout(self) -> None:
        if self._token:
            session.zero_trust.logout(self._token)
        self._token = ""
        self.token_label.setText("no session")
        self._refresh_audit()

    def _authorize(self) -> None:
        if not self._token:
            QMessageBox.warning(self, "No session", "Login first.")
            return
        allowed, reason = session.zero_trust.authorize(self._token, self.path_edit.text())
        self.authz_result.setText("ALLOWED" if allowed else f"DENIED ({reason})")
        self.authz_result.setStyleSheet(
            "color:#2ecc71; font-weight:700;" if allowed else "color:#e74c3c; font-weight:700;"
        )
        self._refresh_audit()

    def _refresh_audit(self) -> None:
        entries = session.zero_trust.get_audit_log(limit=100)
        self.audit_table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            success = str(entry.get("success", ""))
            values = (
                str(entry.get("timestamp", ""))[:19],
                entry.get("username", ""),
                entry.get("action", ""),
                entry.get("ip_address", ""),
                success,
                entry.get("details", ""),
            )
            for col, text in enumerate(values):
                item = QTableWidgetItem(str(text))
                if col == 4:
                    item.setForeground(QColor("#2ecc71" if success == "True" else "#e74c3c"))
                self.audit_table.setItem(row, col, item)
        header = self.audit_table.horizontalHeader()
        header.setSectionResizeMode(5, header.ResizeMode.Stretch)
        self.audit_table.resizeRowsToContents()
