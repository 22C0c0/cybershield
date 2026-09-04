"""Tests for shared libraries."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shared.config import load_config, AppConfig
from shared.crypto import sha256, md5, file_hash, generate_secret
from shared.logger import get_logger
from shared.models import Alert, Severity, AlertStatus, ThreatIndicator


class TestConfig:
    def test_load_config_returns_app_config(self):
        config = load_config()
        assert isinstance(config, AppConfig)

    def test_config_has_defaults(self):
        config = load_config()
        assert config.name == "cybershield"
        assert config.log_level in ("INFO", "DEBUG", "WARNING", "ERROR")


class TestCrypto:
    def test_sha256(self):
        result = sha256(b"hello world")
        assert result == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"

    def test_md5(self):
        result = md5(b"hello")
        assert result == "5d41402abc4b2a76b9719d911017c592"

    def test_file_hash(self, tmp_path):
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello world")
        hashes = file_hash(test_file)
        assert "sha256" in hashes
        assert "md5" in hashes
        assert "sha1" in hashes
        assert len(hashes["sha256"]) == 64

    def test_generate_secret(self):
        secret = generate_secret()
        assert len(secret) > 0
        secret2 = generate_secret()
        assert secret != secret2


class TestModels:
    def test_alert_creation(self):
        alert = Alert(
            module="test",
            title="Test Alert",
            severity=Severity.HIGH,
        )
        assert alert.module == "test"
        assert alert.severity == Severity.HIGH
        assert alert.status == AlertStatus.OPEN

    def test_alert_to_dict(self):
        alert = Alert(module="test", title="Test", severity=Severity.LOW)
        d = alert.to_dict()
        assert d["module"] == "test"
        assert d["severity"] == "low"

    def test_threat_indicator(self):
        indicator = ThreatIndicator(
            indicator_type="ip",
            value="192.168.1.100",
            confidence=0.85,
        )
        assert indicator.indicator_type == "ip"
        d = indicator.to_dict()
        assert d["confidence"] == 0.85


class TestLogger:
    def test_get_logger(self):
        logger = get_logger("test")
        assert logger is not None
        assert logger.name == "test"

    def test_logger_singleton(self):
        logger1 = get_logger("test_singleton")
        logger2 = get_logger("test_singleton")
        assert logger1 is logger2
