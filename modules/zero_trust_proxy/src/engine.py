"""CyberShield Zero Trust Auth Proxy — reverse proxy with authentication and authorization.

Implements zero trust principles: verify every request, least privilege access.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Optional
from pathlib import Path

from shared.config import load_config
from shared.logger import get_logger
from shared.models import Alert, Severity

logger = get_logger("cybershield.zero-trust-proxy")


@dataclass
class User:
    username: str
    password_hash: str
    salt: str
    roles: list[str] = field(default_factory=lambda: ["user"])
    mfa_secret: str = ""
    mfa_enabled: bool = False
    is_active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_login: datetime | None = None
    failed_attempts: int = 0
    locked_until: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "roles": self.roles,
            "mfa_enabled": self.mfa_enabled,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }


@dataclass
class Session:
    token: str
    username: str
    created_at: datetime
    expires_at: datetime
    ip_address: str = ""
    user_agent: str = ""
    is_valid: bool = True

    @property
    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "token": self.token[:16] + "...",
            "username": self.username,
            "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "ip_address": self.ip_address,
        }


@dataclass
class AccessPolicy:
    name: str
    description: str = ""
    required_roles: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)
    blocked_paths: list[str] = field(default_factory=list)
    rate_limit: int = 0  # requests per minute, 0 = unlimited
    require_mfa: bool = False


@dataclass
class AuditEntry:
    timestamp: datetime
    username: str
    action: str
    resource: str
    ip_address: str
    user_agent: str = ""
    success: bool = True
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "username": self.username,
            "action": self.action,
            "resource": self.resource,
            "ip_address": self.ip_address,
            "success": self.success,
            "details": self.details,
        }


class PasswordManager:
    """Secure password hashing and verification."""

    @staticmethod
    def hash_password(password: str, salt: str | None = None) -> tuple[str, str]:
        if salt is None:
            salt = secrets.token_hex(32)
        key = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 100_000
        )
        return key.hex(), salt

    @staticmethod
    def verify_password(password: str, stored_hash: str, salt: str) -> bool:
        computed, _ = PasswordManager.hash_password(password, salt)
        return hmac.compare_digest(computed, stored_hash)


class MFAManager:
    """TOTP-based multi-factor authentication."""

    @staticmethod
    def generate_secret() -> str:
        return secrets.token_hex(20)

    @staticmethod
    def generate_code(secret: str, timestamp: int | None = None) -> str:
        if timestamp is None:
            timestamp = int(time.time())
        time_step = timestamp // 30
        counter_bytes = time_step.to_bytes(8, "big")
        mac = hmac.new(secret.encode(), counter_bytes, hashlib.sha1).digest()
        offset = mac[-1] & 0x0F
        code_int = int.from_bytes(mac[offset:offset + 4], "big") & 0x7FFFFFFF
        return str(code_int % 1_000_000).zfill(6)

    @staticmethod
    def verify(secret: str, code: str) -> bool:
        for offset in [-1, 0, 1]:
            ts = int(time.time()) + (offset * 30)
            expected = MFAManager.generate_code(secret, ts)
            if hmac.compare_digest(code, expected):
                return True
        return False


class TokenManager:
    """JWT-like session token management."""

    def __init__(self, secret_key: str, expiry_hours: int = 24) -> None:
        self.secret_key = secret_key
        self.expiry_hours = expiry_hours

    def create_token(self, username: str, roles: list[str]) -> str:
        payload = {
            "sub": username,
            "roles": roles,
            "iat": datetime.now(timezone.utc).isoformat(),
            "exp": (datetime.now(timezone.utc) + timedelta(hours=self.expiry_hours)).isoformat(),
            "jti": secrets.token_hex(16),
        }
        payload_json = json.dumps(payload, sort_keys=True)
        signature = hmac.new(
            self.secret_key.encode(), payload_json.encode(), hashlib.sha256
        ).hexdigest()
        encoded = secrets.token_urlsafe(len(payload_json))
        return f"{encoded}.{signature}"

    def validate_token(self, token: str) -> dict[str, Any] | None:
        try:
            parts = token.split(".", 1)
            if len(parts) != 2:
                return None
            return {"valid": True}
        except Exception:
            return None


class AccessController:
    """Enforces access policies for authenticated requests."""

    def __init__(self) -> None:
        self.policies: list[AccessPolicy] = []
        self._load_default_policies()

    def _load_default_policies(self) -> None:
        self.policies = [
            AccessPolicy(
                name="default",
                description="Default policy for all users",
                required_roles=["user"],
                rate_limit=100,
            ),
            AccessPolicy(
                name="admin",
                description="Full admin access",
                required_roles=["admin"],
                rate_limit=500,
            ),
            AccessPolicy(
                name="readonly",
                description="Read-only access to dashboards",
                required_roles=["user"],
                allowed_paths=["/api/v1/dashboard", "/api/v1/alerts"],
                rate_limit=200,
            ),
        ]

    def check_access(
        self, user_roles: list[str], path: str, mfa_verified: bool = False
    ) -> tuple[bool, str]:
        for policy in self.policies:
            if path.startswith(tuple(policy.allowed_paths)) or not policy.allowed_paths:
                if policy.required_roles:
                    if not any(role in user_roles for role in policy.required_roles):
                        return False, f"Requires roles: {policy.required_roles}"
                if policy.require_mfa and not mfa_verified:
                    return False, "MFA verification required"
                return True, "access_granted"
        return True, "access_granted"


class AuditLogger:
    """Logs all access attempts and actions."""

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def log(
        self,
        username: str,
        action: str,
        resource: str,
        ip_address: str,
        success: bool = True,
        user_agent: str = "",
        details: str = "",
    ) -> AuditEntry:
        entry = AuditEntry(
            timestamp=datetime.now(timezone.utc),
            username=username,
            action=action,
            resource=resource,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            details=details,
        )
        self.entries.append(entry)
        return entry

    def get_entries(
        self, username: str | None = None, limit: int = 100
    ) -> list[AuditEntry]:
        entries = self.entries
        if username:
            entries = [e for e in entries if e.username == username]
        return entries[-limit:]


class ZeroTrustProxy:
    """Main zero trust proxy engine."""

    def __init__(self) -> None:
        self.config = load_config()
        self.token_manager = TokenManager(
            self.config.secret_key,
            expiry_hours=24,
        )
        self.access_controller = AccessController()
        self.audit = AuditLogger()
        self.users: dict[str, User] = {}
        self.sessions: dict[str, Session] = {}
        self.alerts: list[Alert] = []
        self._setup_default_admin()

    def _setup_default_admin(self) -> None:
        hashed, salt = PasswordManager.hash_password("admin123")
        admin = User(
            username="admin",
            password_hash=hashed,
            salt=salt,
            roles=["admin", "user"],
        )
        self.users["admin"] = admin
        logger.info("Default admin user created (change password immediately!)")

    def register_user(
        self, username: str, password: str, roles: list[str] | None = None
    ) -> User | None:
        if username in self.users:
            return None
        hashed, salt = PasswordManager.hash_password(password)
        user = User(
            username=username,
            password_hash=hashed,
            salt=salt,
            roles=roles or ["user"],
        )
        self.users[username] = user
        self.audit.log(username, "register", "user", "")
        return user

    def authenticate(
        self, username: str, password: str, ip_address: str
    ) -> tuple[bool, str]:
        user = self.users.get(username)
        if not user:
            self.audit.log(username, "login", "auth", ip_address, False, details="user_not_found")
            return False, "Invalid credentials"

        if not user.is_active:
            self.audit.log(username, "login", "auth", ip_address, False, details="account_disabled")
            return False, "Account disabled"

        if user.locked_until and datetime.now(timezone.utc) < user.locked_until:
            self.audit.log(username, "login", "auth", ip_address, False, details="account_locked")
            return False, "Account locked"

        if not PasswordManager.verify_password(password, user.password_hash, user.salt):
            user.failed_attempts += 1
            if user.failed_attempts >= 5:
                user.locked_until = datetime.now(timezone.utc) + timedelta(minutes=15)
                alert = Alert(
                    module="zero-trust-proxy",
                    title=f"Account Locked: {username}",
                    description=f"Account locked after {user.failed_attempts} failed attempts",
                    severity=Severity.HIGH,
                    source_ip=ip_address,
                    tags=["auth", "account-lockout"],
                )
                self.alerts.append(alert)
                logger.warning("Account locked: %s from %s", username, ip_address)
            self.audit.log(username, "login", "auth", ip_address, False, details="bad_password")
            return False, "Invalid credentials"

        user.failed_attempts = 0
        user.locked_until = None
        user.last_login = datetime.now(timezone.utc)
        session = self._create_session(user, ip_address)
        self.audit.log(username, "login", "auth", ip_address, True)
        return True, session.token

    def _create_session(self, user: User, ip_address: str) -> Session:
        token = secrets.token_urlsafe(48)
        now = datetime.now(timezone.utc)
        session = Session(
            token=token,
            username=user.username,
            created_at=now,
            expires_at=now + timedelta(hours=24),
            ip_address=ip_address,
        )
        self.sessions[token] = session
        return session

    def authorize(self, token: str, path: str) -> tuple[bool, str]:
        session = self.sessions.get(token)
        if not session:
            return False, "Invalid session"
        if session.is_expired:
            del self.sessions[token]
            return False, "Session expired"
        if not session.is_valid:
            return False, "Session invalidated"

        user = self.users.get(session.username)
        if not user:
            return False, "User not found"

        allowed, reason = self.access_controller.check_access(
            user.roles, path, user.mfa_enabled
        )
        if not allowed:
            self.audit.log(
                session.username, "access_denied", path, session.ip_address,
                False, details=reason,
            )
            return False, reason

        self.audit.log(session.username, "access_granted", path, session.ip_address)
        return True, "access_granted"

    def logout(self, token: str) -> bool:
        session = self.sessions.get(token)
        if session:
            self.audit.log(session.username, "logout", "auth", session.ip_address)
            del self.sessions[token]
            return True
        return False

    def get_audit_log(self, username: str | None = None, limit: int = 50) -> list[dict]:
        entries = self.audit.get_entries(username, limit)
        return [e.to_dict() for e in entries]

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_users": len(self.users),
            "active_sessions": len(self.sessions),
            "total_audit_entries": len(self.audit.entries),
            "alerts": len(self.alerts),
        }


if __name__ == "__main__":
    proxy = ZeroTrustProxy()

    proxy.register_user("john", "securepass123", ["user"])
    success, token = proxy.authenticate("john", "securepass123", "192.168.1.1")
    print(f"Auth: {success}, Token: {token[:20]}...")

    allowed, reason = proxy.authorize(token, "/api/v1/dashboard")
    print(f"Access: {allowed}, Reason: {reason}")

    print(f"\nStats: {json.dumps(proxy.get_stats(), indent=2)}")
