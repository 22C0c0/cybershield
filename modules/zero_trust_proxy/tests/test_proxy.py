"""Tests for the Zero Trust Proxy module."""

from __future__ import annotations

from modules.zero_trust_proxy.src.engine import (
    MFAManager,
    PasswordManager,
    ZeroTrustProxy,
)


class TestPasswordManager:
    def test_hash_password(self):
        hashed, salt = PasswordManager.hash_password("mypassword")
        assert len(hashed) == 64
        assert len(salt) == 64

    def test_verify_correct_password(self):
        hashed, salt = PasswordManager.hash_password("correct")
        assert PasswordManager.verify_password("correct", hashed, salt) is True

    def test_verify_wrong_password(self):
        hashed, salt = PasswordManager.hash_password("correct")
        assert PasswordManager.verify_password("wrong", hashed, salt) is False


class TestMFAManager:
    def test_generate_secret(self):
        secret = MFAManager.generate_secret()
        assert len(secret) == 40

    def test_generate_and_verify_code(self):
        secret = MFAManager.generate_secret()
        import time

        code = MFAManager.generate_code(secret, int(time.time()))
        assert len(code) == 6
        assert MFAManager.verify(secret, code) is True

    def test_verify_wrong_code(self):
        secret = MFAManager.generate_secret()
        assert MFAManager.verify(secret, "000000") is False


class TestZeroTrustProxy:
    def test_register_user(self):
        proxy = ZeroTrustProxy()
        user = proxy.register_user("testuser", "pass123")
        assert user is not None
        assert user.username == "testuser"

    def test_duplicate_registration(self):
        proxy = ZeroTrustProxy()
        proxy.register_user("testuser", "pass123")
        result = proxy.register_user("testuser", "pass456")
        assert result is None

    def test_authenticate_success(self):
        proxy = ZeroTrustProxy()
        proxy.register_user("john", "secure123")
        success, token = proxy.authenticate("john", "secure123", "192.168.1.1")
        assert success is True
        assert len(token) > 0

    def test_authenticate_wrong_password(self):
        proxy = ZeroTrustProxy()
        proxy.register_user("john", "secure123")
        success, msg = proxy.authenticate("john", "wrong", "192.168.1.1")
        assert success is False
        assert "Invalid" in msg

    def test_authenticate_nonexistent_user(self):
        proxy = ZeroTrustProxy()
        success, msg = proxy.authenticate("ghost", "pass", "1.1.1.1")
        assert success is False

    def test_authorize_valid_token(self):
        proxy = ZeroTrustProxy()
        proxy.register_user("john", "secure123")
        _, token = proxy.authenticate("john", "secure123", "1.1.1.1")
        allowed, reason = proxy.authorize(token, "/api/v1/dashboard")
        assert allowed is True

    def test_authorize_invalid_token(self):
        proxy = ZeroTrustProxy()
        allowed, reason = proxy.authorize("fake-token", "/api/v1/dashboard")
        assert allowed is False

    def test_logout(self):
        proxy = ZeroTrustProxy()
        proxy.register_user("john", "secure123")
        _, token = proxy.authenticate("john", "secure123", "1.1.1.1")
        assert proxy.logout(token) is True
        allowed, _ = proxy.authorize(token, "/api/v1/test")
        assert allowed is False

    def test_account_lockout(self):
        proxy = ZeroTrustProxy()
        proxy.register_user("john", "secure123")
        for _ in range(5):
            proxy.authenticate("john", "wrong", "1.1.1.1")
        success, msg = proxy.authenticate("john", "secure123", "1.1.1.1")
        assert success is False
        assert "locked" in msg.lower()

    def test_audit_log(self):
        proxy = ZeroTrustProxy()
        proxy.register_user("john", "secure123")
        proxy.authenticate("john", "secure123", "1.1.1.1")
        entries = proxy.get_audit_log()
        assert len(entries) > 0

    def test_get_stats(self):
        proxy = ZeroTrustProxy()
        stats = proxy.get_stats()
        assert "total_users" in stats
        assert stats["total_users"] >= 1  # default admin
