"""CyberShield SIEM — Security Information and Event Management.

Centralized log ingestion, correlation, and alerting engine.
"""

from __future__ import annotations

import json
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from shared.config import load_config
from shared.logger import get_logger
from shared.models import Alert, AlertStatus, Severity

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

logger = get_logger("cybershield.siem")


@dataclass
class LogEntry:
    timestamp: datetime
    source: str
    message: str
    level: str = "info"
    source_ip: str = ""
    user: str = ""
    event_type: str = ""
    raw: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "message": self.message,
            "level": self.level,
            "source_ip": self.source_ip,
            "user": self.user,
            "event_type": self.event_type,
            "metadata": self.metadata,
        }


@dataclass
class DetectionRule:
    name: str
    description: str
    severity: Severity
    condition: Callable[[LogEntry], bool]
    tags: list[str] = field(default_factory=list)
    throttle_seconds: int = 0  # min time between alerts
    _last_fired: float = 0.0

    def evaluate(self, entry: LogEntry) -> bool:
        if self.throttle_seconds > 0 and time.time() - self._last_fired < self.throttle_seconds:
            return False
        try:
            if self.condition(entry):
                self._last_fired = time.time()
                return True
        except Exception as e:
            logger.debug("Rule evaluation failed: %s", e)
        return False


class LogParser:
    """Parses various log formats into LogEntry objects."""

    PATTERNS = {
        "syslog": re.compile(
            r"(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\S+)\s+(?P<host>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)",
        ),
        "apache": re.compile(
            r'(?P<ip>[\d.]+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<size>\d+)',
        ),
        "ssh_failed": re.compile(
            r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)",
        ),
        "auth": re.compile(
            r"(?P<user>\S+)\s+:\s+(?P<message>.*?)(?:\s+from\s+(?P<ip>[\d.]+))?$",
        ),
    }

    def parse_line(self, line: str, source: str = "unknown") -> LogEntry | None:
        line = line.strip()
        if not line:
            return None

        entry = LogEntry(
            timestamp=datetime.now(UTC),
            source=source,
            message=line,
            raw=line,
        )

        for name, pattern in self.PATTERNS.items():
            match = pattern.search(line)
            if match:
                groups = match.groupdict()
                if "ip" in groups:
                    entry.source_ip = groups["ip"]
                if "user" in groups:
                    entry.user = groups["user"]
                if "message" in groups:
                    entry.message = groups["message"]
                entry.event_type = name
                break

        if "error" in line.lower() or "fail" in line.lower():
            entry.level = "error"
        elif "warn" in line.lower():
            entry.level = "warning"

        return entry


class DetectionEngine:
    """Evaluates log entries against detection rules."""

    def __init__(self) -> None:
        self.rules: list[DetectionRule] = []
        self._load_default_rules()

    def _load_default_rules(self) -> None:
        self.rules = [
            DetectionRule(
                name="Brute Force SSH",
                description="Multiple failed SSH login attempts from same IP",
                severity=Severity.HIGH,
                condition=lambda e: (
                    e.event_type == "ssh_failed"
                    or ("failed password" in e.message.lower() and "sshd" in e.source)
                ),
                tags=["brute-force", "ssh"],
                throttle_seconds=300,
            ),
            DetectionRule(
                name="Authentication Failure",
                description="Authentication failure detected",
                severity=Severity.MEDIUM,
                condition=lambda e: (
                    "authentication failure" in e.message.lower()
                    or "auth fail" in e.message.lower()
                ),
                tags=["auth", "failure"],
                throttle_seconds=60,
            ),
            DetectionRule(
                name="Privilege Escalation Attempt",
                description="Possible privilege escalation detected",
                severity=Severity.CRITICAL,
                condition=lambda e: (
                    "sudo" in e.message.lower()
                    and ("command" in e.message.lower() or "error" in e.message.lower())
                ),
                tags=["privilege-escalation", "sudo"],
            ),
            DetectionRule(
                name="Critical System Error",
                description="Critical error in system service",
                severity=Severity.HIGH,
                condition=lambda e: (
                    e.level == "error"
                    and any(
                        svc in e.source.lower() for svc in ["kernel", "systemd", "cron", "sshd"]
                    )
                ),
                tags=["system", "critical"],
                throttle_seconds=120,
            ),
            DetectionRule(
                name="Suspicious Web Request",
                description="Potential web attack detected in HTTP logs",
                severity=Severity.HIGH,
                condition=lambda e: (
                    e.event_type == "apache"
                    and any(
                        attack in e.message.lower()
                        for attack in ["../../", "<script", "union select", "exec(", "cmd.exe"]
                    )
                ),
                tags=["web", "attack"],
            ),
            DetectionRule(
                name="New User Created",
                description="New user account created on system",
                severity=Severity.MEDIUM,
                condition=lambda e: (
                    "user added" in e.message.lower()
                    or "new user" in e.message.lower()
                    or "useradd" in e.message.lower()
                ),
                tags=["account", "creation"],
            ),
            DetectionRule(
                name="Firewall Block",
                description="Firewall blocked connection",
                severity=Severity.LOW,
                condition=lambda e: (
                    "blocked" in e.message.lower()
                    or "drop" in e.message.lower()
                    or "reject" in e.message.lower()
                ),
                tags=["firewall", "network"],
                throttle_seconds=60,
            ),
        ]

    def add_rule(self, rule: DetectionRule) -> None:
        self.rules.append(rule)

    def evaluate(self, entry: LogEntry) -> list[Alert]:
        alerts = []
        for rule in self.rules:
            if rule.evaluate(entry):
                alert = Alert(
                    module="siem",
                    title=f"Rule: {rule.name}",
                    description=rule.description,
                    severity=rule.severity,
                    source_ip=entry.source_ip,
                    tags=rule.tags,
                    metadata={"log_entry": entry.to_dict(), "rule": rule.name},
                )
                alerts.append(alert)
                logger.warning("Detection: %s | %s", rule.name, entry.message[:200])
        return alerts


class AlertStore:
    """In-memory alert store with correlation capabilities."""

    def __init__(self) -> None:
        self.alerts: list[Alert] = []
        self._ip_correlation: dict[str, list[Alert]] = defaultdict(list)

    def add(self, alert: Alert) -> None:
        self.alerts.append(alert)
        if alert.source_ip:
            self._ip_correlation[alert.source_ip].append(alert)

    def get_alerts(
        self,
        severity: Severity | None = None,
        status: AlertStatus | None = None,
        source_ip: str | None = None,
        limit: int = 100,
    ) -> list[Alert]:
        results = self.alerts
        if severity:
            results = [a for a in results if a.severity == severity]
        if status:
            results = [a for a in results if a.status == status]
        if source_ip:
            results = [a for a in results if a.source_ip == source_ip]
        return results[-limit:]

    def get_correlated(self, ip: str) -> list[Alert]:
        return self._ip_correlation.get(ip, [])

    def get_stats(self) -> dict[str, Any]:
        severity_counts = defaultdict(int)
        for alert in self.alerts:
            severity_counts[alert.severity.value] += 1
        return {
            "total_alerts": len(self.alerts),
            "by_severity": dict(severity_counts),
            "unique_source_ips": len(self._ip_correlation),
        }


class SIEMEngine:
    """Main SIEM engine — coordinates log ingestion, parsing, detection, and storage."""

    def __init__(self) -> None:
        self.config = load_config()
        self.parser = LogParser()
        self.detection = DetectionEngine()
        self.alert_store = AlertStore()
        self.log_count = 0

    def ingest_log(self, raw_line: str, source: str = "unknown") -> list[Alert]:
        entry = self.parser.parse_line(raw_line, source)
        if entry is None:
            return []
        self.log_count += 1
        alerts = self.detection.evaluate(entry)
        for alert in alerts:
            self.alert_store.add(alert)
        return alerts

    def ingest_batch(self, lines: list[str], source: str = "unknown") -> list[Alert]:
        all_alerts = []
        for line in lines:
            alerts = self.ingest_log(line, source)
            all_alerts.extend(alerts)
        return all_alerts

    def ingest_file(self, file_path: Path, source: str = "file") -> list[Alert]:
        alerts = []
        try:
            with file_path.open() as f:
                for line in f:
                    line_alerts = self.ingest_log(line, source)
                    alerts.extend(line_alerts)
        except OSError as e:
            logger.error("Failed to read log file %s: %s", file_path, e)
        return alerts

    def load_rules_from_file(self, rules_path: Path) -> None:
        try:
            with rules_path.open() as f:
                rules_data = json.load(f)
            for rule_def in rules_data.get("rules", []):
                pattern = rule_def.get("pattern", "")
                rule = DetectionRule(
                    name=rule_def["name"],
                    description=rule_def.get("description", ""),
                    severity=Severity(rule_def.get("severity", "medium")),
                    condition=lambda e, pattern=pattern: pattern in e.message.lower(),
                    tags=rule_def.get("tags", []),
                    throttle_seconds=rule_def.get("throttle_seconds", 0),
                )
                self.detection.add_rule(rule)
            logger.info("Loaded %d rules from %s", len(rules_data.get("rules", [])), rules_path)
        except Exception as e:
            logger.error("Failed to load rules: %s", e)

    def get_stats(self) -> dict[str, Any]:
        return {
            "logs_processed": self.log_count,
            "alerts": self.alert_store.get_stats(),
            "active_rules": len(self.detection.rules),
        }


if __name__ == "__main__":
    engine = SIEMEngine()
    test_logs = [
        "Failed password for root from 192.168.1.100 port 22 ssh2",
        "Accepted publickey for admin from 10.0.0.5 port 443 ssh2",
        (
            "sudo: user : command not allowed ; TTY=pts/0 ; PWD=/home/user ; "
            "USER=root ; COMMAND=/bin/cat /etc/shadow"
        ),
        "kernel: [UFW BLOCK] IN=eth0 OUT= SRC=172.16.0.1 DST=10.0.0.1",
    ]
    for log in test_logs:
        alerts = engine.ingest_log(log, "test")
        for a in alerts:
            print(f"ALERT: {a.title} | {a.severity.value}")
    print(f"\nStats: {json.dumps(engine.get_stats(), indent=2)}")
