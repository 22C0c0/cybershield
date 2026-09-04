"""CyberShield GUI — shared engine session.

Holds a single instance of every module engine so all tabs operate on the
same in-memory state (alerts, stats, sessions, findings).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from modules.malware_sandbox.src.engine import MalwareSandbox
from modules.nids.src.engine import NIDSEngine
from modules.secrets_detector.src.engine import SecretsDetector
from modules.siem.src.engine import SIEMEngine
from modules.vuln_scanner.src.engine import VulnScanner
from modules.zero_trust_proxy.src.engine import ZeroTrustProxy

if TYPE_CHECKING:
    from shared.models import Alert


class GuiSession:
    """Central registry of engine instances shared across GUI tabs."""

    def __init__(self) -> None:
        self.nids = NIDSEngine()
        self.sandbox = MalwareSandbox()
        self.vuln = VulnScanner()
        self.siem = SIEMEngine()
        self.zero_trust = ZeroTrustProxy()
        self.secrets = SecretsDetector()
        self.sandbox_alerts: list[Alert] = []

    def all_alerts(self) -> list[dict]:
        """Collect alerts from every module into a single list (newest first)."""
        alerts: list[dict] = []
        for alert in (*self.nids.alerts, *self.sandbox_alerts, *self.vuln.alerts):
            alerts.append(alert.to_dict())
        alerts.extend(a.to_dict() for a in self.siem.alert_store.get_alerts(limit=500))
        alerts.extend(a.to_dict() for a in self.zero_trust.alerts)
        alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
        return alerts


session: GuiSession = GuiSession()
