"""CyberShield Secrets Detector — scans repositories for leaked credentials and secrets.

Detects API keys, passwords, private keys, and other sensitive data in code.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shared.logger import get_logger
from shared.models import Alert, Severity

logger = get_logger("cybershield.secrets-detector")


@dataclass
class SecretPattern:
    name: str
    pattern: re.Pattern
    severity: Severity
    description: str = ""
    tags: list[str] = field(default_factory=list)
    entropy_threshold: float = 0.0  # min entropy to flag


@dataclass
class Finding:
    file_path: str
    line_number: int
    line_content: str
    pattern_name: str
    severity: Severity
    matched_text: str
    description: str = ""
    tags: list[str] = field(default_factory=list)
    entropy: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "file": self.file_path,
            "line": self.line_number,
            "pattern": self.pattern_name,
            "severity": self.severity.value,
            "matched": self.matched_text[:50] + "..." if len(self.matched_text) > 50 else self.matched_text,
            "description": self.description,
            "tags": self.tags,
            "entropy": round(self.entropy, 4),
        }


class SecretPatterns:
    """Built-in patterns for detecting secrets and credentials."""

    @staticmethod
    def get_default_patterns() -> list[SecretPattern]:
        return [
            SecretPattern(
                name="AWS Access Key",
                pattern=re.compile(r"AKIA[0-9A-Z]{16}"),
                severity=Severity.CRITICAL,
                description="AWS Access Key ID detected",
                tags=["aws", "cloud", "api-key"],
            ),
            SecretPattern(
                name="AWS Secret Key",
                pattern=re.compile(r"(?i)aws(.{0,10})?['\"]?[0-9a-zA-Z/+=]{40}['\"]?"),
                severity=Severity.CRITICAL,
                description="AWS Secret Access Key detected",
                tags=["aws", "cloud", "secret-key"],
            ),
            SecretPattern(
                name="GitHub Token",
                pattern=re.compile(r"ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z]{82}"),
                severity=Severity.CRITICAL,
                description="GitHub Personal Access Token detected",
                tags=["github", "token"],
            ),
            SecretPattern(
                name="GitLab Token",
                pattern=re.compile(r"glpat-[0-9a-zA-Z\-]{20,}"),
                severity=Severity.CRITICAL,
                description="GitLab Personal Access Token detected",
                tags=["gitlab", "token"],
            ),
            SecretPattern(
                name="Slack Token",
                pattern=re.compile(r"xox[baprs]-[0-9a-zA-Z\-]{10,}"),
                severity=Severity.HIGH,
                description="Slack token detected",
                tags=["slack", "token"],
            ),
            SecretPattern(
                name="Slack Webhook",
                pattern=re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"),
                severity=Severity.HIGH,
                description="Slack Webhook URL detected",
                tags=["slack", "webhook"],
            ),
            SecretPattern(
                name="Google API Key",
                pattern=re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
                severity=Severity.HIGH,
                description="Google API Key detected",
                tags=["google", "api-key"],
            ),
            SecretPattern(
                name="Google OAuth",
                pattern=re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
                severity=Severity.HIGH,
                description="Google OAuth Client ID detected",
                tags=["google", "oauth"],
            ),
            SecretPattern(
                name="Stripe API Key",
                pattern=re.compile(r"sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,}"),
                severity=Severity.CRITICAL,
                description="Stripe API Key detected",
                tags=["stripe", "payment", "api-key"],
            ),
            SecretPattern(
                name="Private Key Block",
                pattern=re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
                severity=Severity.CRITICAL,
                description="Private key file detected",
                tags=["private-key", "crypto"],
            ),
            SecretPattern(
                name="Password in Code",
                pattern=re.compile(
                    r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']',
                    re.IGNORECASE,
                ),
                severity=Severity.HIGH,
                description="Hardcoded password detected",
                tags=["password", "hardcoded"],
            ),
            SecretPattern(
                name="API Key Assignment",
                pattern=re.compile(
                    r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][^"\']{16,}["\']',
                    re.IGNORECASE,
                ),
                severity=Severity.HIGH,
                description="Hardcoded API key detected",
                tags=["api-key", "hardcoded"],
            ),
            SecretPattern(
                name="Connection String",
                pattern=re.compile(
                    r'(?i)(mysql|postgres|mongodb|redis|amqp)://[^\s"\'<>]{20,}',
                    re.IGNORECASE,
                ),
                severity=Severity.CRITICAL,
                description="Database connection string with credentials detected",
                tags=["database", "connection-string"],
            ),
            SecretPattern(
                name="JWT Token",
                pattern=re.compile(r"eyJ[0-9a-zA-Z_-]{10,}\.eyJ[0-9a-zA-Z_-]{10,}\.[0-9a-zA-Z_-]+"),
                severity=Severity.MEDIUM,
                description="JWT token detected in code",
                tags=["jwt", "token"],
            ),
            SecretPattern(
                name="AWS ARN",
                pattern=re.compile(r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:[a-zA-Z0-9/_-]+"),
                severity=Severity.LOW,
                description="AWS ARN detected (review for exposure)",
                tags=["aws", "arn"],
            ),
            SecretPattern(
                name="IP Address with Port",
                pattern=re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\b"),
                severity=Severity.LOW,
                description="Internal IP with port detected",
                tags=["network", "internal"],
            ),
            SecretPattern(
                name="High Entropy String",
                pattern=re.compile(r"[a-zA-Z0-9+/=]{40,}"),
                severity=Severity.LOW,
                description="High entropy string (potential secret)",
                tags=["entropy"],
                entropy_threshold=4.5,
            ),
        ]


class EntropyCalculator:
    """Calculates Shannon entropy of strings."""

    @staticmethod
    def calculate(text: str) -> float:
        import math
        if not text:
            return 0.0
        freq: dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        length = len(text)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())


class SecretsDetector:
    """Main secrets detection engine."""

    SKIP_DIRS = {
        ".git", "node_modules", "__pycache__", ".venv", "venv",
        "dist", "build", ".next", "target", "vendor",
    }
    SKIP_EXTENSIONS = {
        ".pyc", ".pyo", ".so", ".dll", ".exe", ".bin",
        ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
        ".mp3", ".mp4", ".wav", ".avi",
        ".zip", ".tar", ".gz", ".rar", ".7z",
        ".woff", ".woff2", ".ttf", ".eot",
    }

    def __init__(self, custom_patterns: list[SecretPattern] | None = None) -> None:
        self.patterns = custom_patterns or SecretPatterns.get_default_patterns()
        self.findings: list[Finding] = []
        self.scanned_files = 0

    def scan_file(self, file_path: Path) -> list[Finding]:
        findings = []
        if file_path.suffix in self.SKIP_EXTENSIONS:
            return findings
        try:
            with open(file_path, "r", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return findings

        self.scanned_files += 1
        for line_num, line in enumerate(lines, 1):
            for pattern in self.patterns:
                match = pattern.pattern.search(line)
                if match:
                    entropy = EntropyCalculator.calculate(match.group())
                    if pattern.entropy_threshold > 0 and entropy < pattern.entropy_threshold:
                        continue
                    finding = Finding(
                        file_path=str(file_path),
                        line_number=line_num,
                        line_content=line.strip(),
                        pattern_name=pattern.name,
                        severity=pattern.severity,
                        matched_text=match.group(),
                        description=pattern.description,
                        tags=pattern.tags,
                        entropy=entropy,
                    )
                    findings.append(finding)
                    logger.warning(
                        "Secret found: %s at %s:%d",
                        pattern.name, file_path, line_num,
                    )
        self.findings.extend(findings)
        return findings

    def scan_directory(self, directory: Path, max_depth: int = 10) -> list[Finding]:
        findings = []
        if not directory.is_dir():
            return findings

        def _scan(path: Path, depth: int = 0) -> None:
            if depth > max_depth:
                return
            try:
                for item in sorted(path.iterdir()):
                    if item.name in self.SKIP_DIRS:
                        continue
                    if item.is_file():
                        findings.extend(self.scan_file(item))
                    elif item.is_dir():
                        _scan(item, depth + 1)
            except PermissionError:
                pass

        _scan(directory)
        return findings

    def scan_git_repo(self, repo_path: Path) -> list[Finding]:
        """Scan a git repository, including staged and unstaged changes."""
        findings = self.scan_directory(repo_path)

        import subprocess
        try:
            result = subprocess.run(
                ["git", "diff", "--cached", "--name-only"],
                capture_output=True, text=True, cwd=repo_path,
            )
            for file_name in result.stdout.strip().split("\n"):
                if file_name:
                    file_path = repo_path / file_name
                    if file_path.exists():
                        findings.extend(self.scan_file(file_path))
        except FileNotFoundError:
            pass

        return findings

    def scan_content(self, content: str, source: str = "inline") -> list[Finding]:
        """Scan raw text content for secrets."""
        findings = []
        for line_num, line in enumerate(content.splitlines(), 1):
            for pattern in self.patterns:
                match = pattern.pattern.search(line)
                if match:
                    entropy = EntropyCalculator.calculate(match.group())
                    if pattern.entropy_threshold > 0 and entropy < pattern.entropy_threshold:
                        continue
                    findings.append(Finding(
                        file_path=source,
                        line_number=line_num,
                        line_content=line.strip(),
                        pattern_name=pattern.name,
                        severity=pattern.severity,
                        matched_text=match.group(),
                        description=pattern.description,
                        tags=pattern.tags,
                        entropy=entropy,
                    ))
        return findings

    def generate_report(self) -> dict[str, Any]:
        severity_counts: dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

        return {
            "total_findings": len(self.findings),
            "files_scanned": self.scanned_files,
            "by_severity": severity_counts,
            "patterns_used": len(self.patterns),
            "findings": [f.to_dict() for f in self.findings],
        }

    def generate_alerts(self) -> list[Alert]:
        alerts = []
        for finding in self.findings:
            if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                alert = Alert(
                    module="secrets-detector",
                    title=f"Secret Found: {finding.pattern_name}",
                    description=finding.description,
                    severity=finding.severity,
                    tags=finding.tags,
                    metadata=finding.to_dict(),
                )
                alerts.append(alert)
        return alerts


if __name__ == "__main__":
    import sys
    target = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")
    detector = SecretsDetector()
    if target.is_dir():
        detector.scan_directory(target)
    else:
        detector.scan_file(target)
    report = detector.generate_report()
    print(json.dumps(report, indent=2))
