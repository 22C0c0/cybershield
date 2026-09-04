"""Tests for the SIEM module."""

from __future__ import annotations

import pytest

from modules.siem.src.engine import (
    SIEMEngine,
    LogParser,
    DetectionEngine,
    AlertStore,
    LogEntry,
)


class TestLogParser:
    def test_parse_ssh_failed(self):
        parser = LogParser()
        entry = parser.parse_line(
            "Failed password for root from 192.168.1.100 port 22 ssh2",
            source="auth",
        )
        assert entry is not None
        assert entry.source_ip == "192.168.1.100"
        assert entry.user == "root"
        assert entry.event_type == "ssh_failed"

    def test_parse_empty_line(self):
        parser = LogParser()
        entry = parser.parse_line("")
        assert entry is None

    def test_parse_error_log(self):
        parser = LogParser()
        entry = parser.parse_line("ERROR: Connection refused", source="app")
        assert entry is not None
        assert entry.level == "error"


class TestDetectionEngine:
    def test_brute_force_detection(self):
        engine = DetectionEngine()
        entry = LogEntry(
            timestamp=None,
            source="sshd",
            message="Failed password for admin from 10.0.0.1 port 22 ssh2",
            source_ip="10.0.0.1",
        )
        import datetime
        entry.timestamp = datetime.datetime.now(datetime.timezone.utc)
        alerts = engine.evaluate(entry)
        assert len(alerts) > 0
        assert any("Brute Force" in a.title for a in alerts)


class TestAlertStore:
    def test_add_and_get(self):
        store = AlertStore()
        from shared.models import Alert, Severity
        alert = Alert(module="test", title="Test", severity=Severity.HIGH)
        store.add(alert)
        alerts = store.get_alerts()
        assert len(alerts) == 1

    def test_filter_by_severity(self):
        store = AlertStore()
        from shared.models import Alert, Severity
        store.add(Alert(module="test", title="High", severity=Severity.HIGH))
        store.add(Alert(module="test", title="Low", severity=Severity.LOW))
        high = store.get_alerts(severity=Severity.HIGH)
        assert len(high) == 1
        assert high[0].title == "High"


class TestSIEMEngine:
    def test_ingest_log(self):
        engine = SIEMEngine()
        alerts = engine.ingest_log(
            "Failed password for root from 192.168.1.100 port 22 ssh2",
            source="test",
        )
        assert engine.log_count == 1

    def test_ingest_batch(self):
        engine = SIEMEngine()
        logs = [
            "Failed password for root from 1.1.1.1 port 22 ssh2",
            "Accepted password for admin from 2.2.2.2 port 22 ssh2",
        ]
        alerts = engine.ingest_batch(logs, source="test")
        assert engine.log_count == 2

    def test_get_stats(self):
        engine = SIEMEngine()
        engine.ingest_log("test log message")
        stats = engine.get_stats()
        assert stats["logs_processed"] == 1
        assert "alerts" in stats
