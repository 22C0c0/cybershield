"""CyberShield NIDS — Network Intrusion Detection System.

High-performance packet capture and threat analysis engine.
Uses scapy for packet parsing and custom ML models for anomaly detection.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Optional

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw  # noqa: F401
from scapy.packet import Packet

from shared.config import load_config
from shared.logger import get_logger
from shared.models import Alert, Severity, ThreatIndicator

logger = get_logger("cybershield.nids")


@dataclass
class PacketStats:
    total_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    suspicious_packets: int = 0
    bytes_captured: int = 0


@dataclass
class Signature:
    name: str
    pattern: bytes
    severity: Severity
    description: str = ""
    tags: list[str] = field(default_factory=list)


class SignatureEngine:
    """Pattern matching engine for known attack signatures."""

    def __init__(self) -> None:
        self.signatures: list[Signature] = []
        self._load_default_signatures()

    def _load_default_signatures(self) -> None:
        default_sigs = [
            Signature(
                name="SQL Injection Attempt",
                pattern=b"UNION SELECT",
                severity=Severity.HIGH,
                tags=["sql-injection", "web"],
            ),
            Signature(
                name="XSS Attempt",
                pattern=b"<script>alert(",
                severity=Severity.HIGH,
                tags=["xss", "web"],
            ),
            Signature(
                name="Shellcode NOP Sled",
                pattern=b"\x90" * 16,
                severity=Severity.CRITICAL,
                tags=["shellcode", "exploit"],
            ),
            Signature(
                name="Reverse Shell",
                pattern=b"/bin/sh",
                severity=Severity.CRITICAL,
                tags=["reverse-shell", "post-exploitation"],
            ),
            Signature(
                name="Directory Traversal",
                pattern=b"../../../",
                severity=Severity.MEDIUM,
                tags=["path-traversal", "web"],
            ),
            Signature(
                name="Credential Dump",
                pattern=b"SAM DATABASE",
                severity=Severity.CRITICAL,
                tags=["credential-theft", "post-exploitation"],
            ),
        ]
        self.signatures.extend(default_sigs)

    def add_signature(self, sig: Signature) -> None:
        self.signatures.append(sig)

    def scan_payload(self, payload: bytes) -> list[Signature]:
        matches = []
        for sig in self.signatures:
            if sig.pattern in payload:
                matches.append(sig)
        return matches


class AnomalyDetector:
    """Detects anomalous traffic patterns."""

    def __init__(self, window_seconds: int = 60, syn_threshold: int = 100) -> None:
        self.window_seconds = window_seconds
        self.syn_threshold = syn_threshold
        self.syn_counter: dict[str, list[float]] = {}

    def check_syn_flood(self, src_ip: str, timestamp: float) -> bool:
        if src_ip not in self.syn_counter:
            self.syn_counter[src_ip] = []
        self.syn_counter[src_ip].append(timestamp)
        cutoff = timestamp - self.window_seconds
        self.syn_counter[src_ip] = [
            t for t in self.syn_counter[src_ip] if t > cutoff
        ]
        return len(self.syn_counter[src_ip]) > self.syn_threshold

    def check_port_scan(self, src_ip: str, dst_port: int, timestamp: float) -> bool:
        key = f"{src_ip}:ports"
        if not hasattr(self, "_port_tracker"):
            self._port_tracker: dict[str, dict[str, list]] = {}
        if key not in self._port_tracker:
            self._port_tracker[key] = {"ports": [], "timestamps": []}
        tracker = self._port_tracker[key]
        if dst_port not in tracker["ports"]:
            tracker["ports"].append(dst_port)
            tracker["timestamps"].append(timestamp)
        cutoff = timestamp - self.window_seconds
        tracker["ports"] = [
            p for p, t in zip(tracker["ports"], tracker["timestamps"]) if t > cutoff
        ]
        tracker["timestamps"] = [t for t in tracker["timestamps"] if t > cutoff]
        return len(set(tracker["ports"])) > 25


class NIDSEngine:
    """Main NIDS engine — coordinates packet capture, signature matching, and anomaly detection."""

    def __init__(self) -> None:
        self.config = load_config()
        self.stats = PacketStats()
        self.signature_engine = SignatureEngine()
        self.anomaly_detector = AnomalyDetector()
        self.alerts: list[Alert] = []

    def _process_packet(self, packet: Packet) -> None:
        self.stats.total_packets += 1
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        timestamp = float(packet.time)

        if packet.haslayer(TCP):
            self.stats.tcp_packets += 1
            tcp_layer = packet[TCP]

            if tcp_layer.flags & 0x02 and not (tcp_layer.flags & 0x10):
                if self.anomaly_detector.check_syn_flood(src_ip, timestamp):
                    self._create_alert(
                        title="SYN Flood Detected",
                        description=f"Possible SYN flood from {src_ip}",
                        severity=Severity.CRITICAL,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        tags=["dos", "syn-flood"],
                    )

            if self.anomaly_detector.check_port_scan(src_ip, tcp_layer.dport, timestamp):
                self._create_alert(
                    title="Port Scan Detected",
                    description=f"Port scan from {src_ip} targeting multiple ports",
                    severity=Severity.MEDIUM,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    tags=["reconnaissance", "port-scan"],
                )

        elif packet.haslayer(UDP):
            self.stats.udp_packets += 1
        elif packet.haslayer(ICMP):
            self.stats.icmp_packets += 1

        if packet.haslayer(Raw):
            payload = bytes(packet[Raw].load)
            self.stats.bytes_captured += len(payload)
            matches = self.signature_engine.scan_payload(payload)
            for match in matches:
                self._create_alert(
                    title=f"Signature Match: {match.name}",
                    description=match.description or f"Detected pattern for {match.name}",
                    severity=match.severity,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    tags=match.tags,
                )

    def _create_alert(
        self,
        title: str,
        description: str,
        severity: Severity,
        source_ip: str = "",
        destination_ip: str = "",
        tags: list[str] | None = None,
    ) -> Alert:
        alert = Alert(
            module="nids",
            title=title,
            description=description,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            tags=tags or [],
        )
        self.alerts.append(alert)
        self.stats.suspicious_packets += 1
        logger.warning(
            "Alert: %s | %s -> %s | %s",
            title, source_ip, destination_ip, severity.value,
        )
        return alert

    def start_capture(self, interface: str = "eth0", packet_count: int = 0) -> None:
        """Start packet capture on specified interface."""
        logger.info("Starting NIDS capture on interface: %s", interface)
        try:
            sniff(
                iface=interface,
                prn=self._process_packet,
                count=packet_count if packet_count > 0 else 0,
                store=False,
            )
        except PermissionError:
            logger.error("Permission denied. Run with sudo or assign CAP_NET_RAW capability.")
            raise

    def get_stats(self) -> dict:
        return {
            "total_packets": self.stats.total_packets,
            "tcp_packets": self.stats.tcp_packets,
            "udp_packets": self.stats.udp_packets,
            "icmp_packets": self.stats.icmp_packets,
            "suspicious_packets": self.stats.suspicious_packets,
            "bytes_captured": self.stats.bytes_captured,
            "alerts_generated": len(self.alerts),
        }


async def run_nids(interface: str = "eth0") -> None:
    """Async entry point for the NIDS module."""
    engine = NIDSEngine()
    logger.info("NIDS Engine initialized. Starting capture...")
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, engine.start_capture, interface)


if __name__ == "__main__":
    import sys

    iface = sys.argv[1] if len(sys.argv) > 1 else "eth0"
    asyncio.run(run_nids(iface))
