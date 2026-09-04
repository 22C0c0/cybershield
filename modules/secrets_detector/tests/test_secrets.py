"""Tests for the Secrets Detector module."""

from __future__ import annotations

from modules.secrets_detector.src.engine import (
    EntropyCalculator,
    Finding,
    SecretPatterns,
    SecretsDetector,
)


class TestEntropyCalculator:
    def test_low_entropy(self):
        assert EntropyCalculator.calculate("aaaa") < 1.5

    def test_high_entropy(self):
        assert EntropyCalculator.calculate("aB3$xK9!mN@pQ7w") > 3.0

    def test_empty_string(self):
        assert EntropyCalculator.calculate("") == 0.0


class TestSecretPatterns:
    def test_default_patterns_exist(self):
        patterns = SecretPatterns.get_default_patterns()
        assert len(patterns) > 5

    def test_pattern_has_required_fields(self):
        patterns = SecretPatterns.get_default_patterns()
        for p in patterns:
            assert p.name
            assert p.pattern
            assert p.severity


class TestSecretsDetector:
    def test_scan_content_finds_aws_key(self):
        detector = SecretsDetector()
        content = "AWS_KEY=AKIAIOSFODNN7EXAMPLE"
        findings = detector.scan_content(content)
        assert len(findings) > 0
        assert any("AWS" in f.pattern_name for f in findings)

    def test_scan_content_finds_private_key(self):
        detector = SecretsDetector()
        content = "-----BEGIN RSA PRIVATE KEY-----"
        findings = detector.scan_content(content)
        assert len(findings) > 0
        assert any("Private Key" in f.pattern_name for f in findings)

    def test_scan_content_finds_password(self):
        detector = SecretsDetector()
        content = 'password = "supersecretpassword123"'
        findings = detector.scan_content(content)
        assert len(findings) > 0
        assert any("Password" in f.pattern_name for f in findings)

    def test_scan_content_finds_github_token(self):
        detector = SecretsDetector()
        content = "token = ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        findings = detector.scan_content(content)
        assert len(findings) > 0

    def test_scan_file(self, tmp_path):
        test_file = tmp_path / "config.py"
        test_file.write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"\nDB_PASS = "mypassword123"')
        detector = SecretsDetector()
        findings = detector.scan_file(test_file)
        assert len(findings) > 0
        assert detector.scanned_files == 1

    def test_scan_directory(self, tmp_path):
        (tmp_path / "secret.py").write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
        (tmp_path / "clean.py").write_text("x = 42")
        detector = SecretsDetector()
        findings = detector.scan_directory(tmp_path)
        assert len(findings) > 0

    def test_skip_git_directory(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("secret = AKIAIOSFODNN7EXAMPLE")
        detector = SecretsDetector()
        findings = detector.scan_directory(tmp_path)
        assert len(findings) == 0

    def test_generate_report(self):
        detector = SecretsDetector()
        detector.scan_content('password = "hardcoded12345678"')
        report = detector.generate_report()
        assert "total_findings" in report
        assert "by_severity" in report

    def test_generate_alerts(self, tmp_path):
        detector = SecretsDetector()
        f = tmp_path / "secret.txt"
        f.write_text('AWS_KEY="AKIAIOSFODNN7EXAMPLE"')
        detector.scan_file(f)
        alerts = detector.generate_alerts()
        assert len(alerts) > 0
        assert alerts[0].module == "secrets-detector"


class TestFinding:
    def test_finding_to_dict(self):
        from shared.models import Severity

        finding = Finding(
            file_path="test.py",
            line_number=1,
            line_content="password = 'secret'",
            pattern_name="Password in Code",
            severity=Severity.HIGH,
            matched_text="password = 'secret'",
        )
        d = finding.to_dict()
        assert d["file"] == "test.py"
        assert d["line"] == 1
        assert d["pattern"] == "Password in Code"
