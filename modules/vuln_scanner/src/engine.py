"""CyberShield Vulnerability Scanner — high-speed network vulnerability assessment.

Scans hosts and networks for known CVEs, misconfigurations, and exposed services.
"""

from __future__ import annotations

import asyncio
import socket
import time
from dataclasses import dataclass, field
from typing import Any

from shared.config import load_config
from shared.logger import get_logger
from shared.models import Alert, Severity

logger = get_logger("cybershield.vuln-scanner")

CVE_DATABASE: dict[str, dict[str, Any]] = {
    "CVE-2021-44228": {
        "name": "Log4Shell",
        "severity": "critical",
        "affected": ["Apache Log4j 2.0-beta9 to 2.14.1"],
        "description": "Remote code execution via JNDI lookup in Log4j",
    },
    "CVE-2023-44487": {
        "name": "HTTP/2 Rapid Reset",
        "severity": "high",
        "affected": ["HTTP/2 implementations"],
        "description": "Denial of service via HTTP/2 rapid reset",
    },
    "CVE-2024-3094": {
        "name": "XZ Utils Backdoor",
        "severity": "critical",
        "affected": ["XZ Utils 5.6.0 to 5.6.1"],
        "description": "Backdoor in XZ Utils allowing SSH authentication bypass",
    },
    "CVE-2023-23397": {
        "name": "Microsoft Outlook EoP",
        "severity": "critical",
        "affected": ["Microsoft Outlook"],
        "description": "Privilege escalation via Outlook NTLM relay",
    },
    "CVE-2021-34527": {
        "name": "PrintNightmare",
        "severity": "critical",
        "affected": ["Windows Print Spooler"],
        "description": "Remote code execution via Windows Print Spooler",
    },
}

SERVICE_SIGNATURES: dict[str, bytes] = {
    "http": b"HTTP/",
    "ssh": b"SSH-",
    "ftp": b"220 ",
    "smtp": b"220 ",
    "mysql": b"5.",
    "redis": b"-ERR",
    "dns": b"",
    "rdp": b"\x03\x00",
    "smb": b"\xff\x53\x4d\x42",
    "telnet": b"\xff\xfd",
}


@dataclass
class PortResult:
    port: int
    state: str  # open, closed, filtered
    service: str = "unknown"
    version: str = ""
    banner: str = ""


@dataclass
class HostResult:
    ip: str
    hostname: str = ""
    os_guess: str = "unknown"
    ports: list[PortResult] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    scan_time: float = 0.0

    @property
    def open_ports(self) -> int:
        return len([p for p in self.ports if p.state == "open"])

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "os_guess": self.os_guess,
            "open_ports": self.open_ports,
            "ports": [
                {"port": p.port, "state": p.state, "service": p.service, "version": p.version}
                for p in self.ports
            ],
            "vulnerabilities": self.vulnerabilities,
            "scan_time": self.scan_time,
        }


class PortScanner:
    """Fast async TCP port scanner."""

    def __init__(self, max_concurrent: int = 500, timeout: float = 1.0) -> None:
        self.max_concurrent = max_concurrent
        self.timeout = timeout

    async def scan_host(self, ip: str, ports: list[int]) -> list[PortResult]:
        semaphore = asyncio.Semaphore(self.max_concurrent)
        tasks = [self._scan_port(ip, port, semaphore) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, PortResult)]

    async def _scan_port(self, ip: str, port: int, semaphore: asyncio.Semaphore) -> PortResult:
        async with semaphore:
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.timeout,
                )
                writer.close()
                await writer.wait_closed()
                banner = await self._grab_banner(ip, port)
                service = self._identify_service(banner)
                return PortResult(port=port, state="open", service=service, banner=banner)
            except (TimeoutError, ConnectionRefusedError, OSError):
                return PortResult(port=port, state="closed")

    async def _grab_banner(self, ip: str, port: int) -> str:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=2.0,
            )
            data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            writer.close()
            await writer.wait_closed()
            return data.decode(errors="replace").strip()[:256]
        except Exception:
            return ""

    def _identify_service(self, banner: str) -> str:
        if not banner:
            return "unknown"
        for service, sig in SERVICE_SIGNATURES.items():
            if sig and banner.encode().startswith(sig):
                return service
        if "HTTP" in banner:
            return "http"
        if "SSH" in banner:
            return "ssh"
        return "unknown"


class VulnerabilityChecker:
    """Checks discovered services against known vulnerabilities."""

    SERVICE_VULNS: dict[str, list[str]] = {
        "http": ["CVE-2021-44228", "CVE-2023-44487"],
        "ssh": [],
        "smb": ["CVE-2021-34527"],
        "rdp": ["CVE-2023-23397"],
        "ftp": [],
        "mysql": [],
    }

    def check(self, port_result: PortResult) -> list[dict[str, Any]]:
        vulns = []
        cve_ids = self.SERVICE_VULNS.get(port_result.service, [])
        for cve_id in cve_ids:
            if cve_id in CVE_DATABASE:
                cve = CVE_DATABASE[cve_id]
                vulns.append(
                    {
                        "cve_id": cve_id,
                        "name": cve["name"],
                        "severity": cve["severity"],
                        "description": cve["description"],
                        "port": port_result.port,
                        "service": port_result.service,
                    }
                )
        if port_result.banner:
            version = self._extract_version(port_result.banner)
            if version:
                for cve_id, cve_data in CVE_DATABASE.items():
                    for affected in cve_data.get("affected", []):
                        if port_result.service in affected.lower():
                            vulns.append(
                                {
                                    "cve_id": cve_id,
                                    "name": cve_data["name"],
                                    "severity": cve_data["severity"],
                                    "description": cve_data["description"],
                                    "port": port_result.port,
                                    "service": port_result.service,
                                    "detected_version": version,
                                }
                            )
        return vulns

    def _extract_version(self, banner: str) -> str:
        import re

        patterns = [
            r"Apache/(\d+\.\d+\.\d+)",
            r"OpenSSH[_ ](\d+\.\d+)",
            r"nginx/(\d+\.\d+\.\d+)",
            r"ProFTPD (\d+\.\d+)",
            r"vsftpd (\d+\.\d+\.\d+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, banner)
            if match:
                return match.group(1)
        return ""


class VulnScanner:
    """Main vulnerability scanner engine."""

    DEFAULT_PORTS = [
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        143,
        443,
        445,
        993,
        995,
        1433,
        1521,
        3306,
        3389,
        5432,
        5900,
        6379,
        8080,
        8443,
        9200,
        27017,
    ]

    def __init__(self) -> None:
        self.config = load_config()
        self.port_scanner = PortScanner(
            max_concurrent=500,
            timeout=1.0,
        )
        self.vuln_checker = VulnerabilityChecker()
        self.results: list[HostResult] = []
        self.alerts: list[Alert] = []

    async def scan_host(
        self,
        ip: str,
        ports: list[int] | None = None,
    ) -> HostResult:
        start = time.time()
        target_ports = ports or self.DEFAULT_PORTS
        logger.info("Scanning host: %s (%d ports)", ip, len(target_ports))

        hostname = await self._resolve_hostname(ip)
        port_results = await self.port_scanner.scan_host(ip, target_ports)

        vulnerabilities = []
        for pr in port_results:
            if pr.state == "open":
                vulns = self.vuln_checker.check(pr)
                vulnerabilities.extend(vulns)

        result = HostResult(
            ip=ip,
            hostname=hostname,
            ports=port_results,
            vulnerabilities=vulnerabilities,
            scan_time=round(time.time() - start, 3),
        )

        for vuln in vulnerabilities:
            alert = Alert(
                module="vuln-scanner",
                title=f"Vulnerability: {vuln['name']} ({vuln['cve_id']})",
                description=vuln["description"],
                severity=Severity(vuln["severity"]),
                source_ip=ip,
                tags=["vulnerability", vuln["cve_id"]],
                metadata=vuln,
            )
            self.alerts.append(alert)

        self.results.append(result)
        return result

    async def scan_network(
        self,
        network: str,
        ports: list[int] | None = None,
    ) -> list[HostResult]:
        import ipaddress

        try:
            hosts = [str(h) for h in ipaddress.ip_network(network, strict=False).hosts()]
        except ValueError:
            hosts = [network]

        logger.info("Scanning network: %s (%d hosts)", network, len(hosts))
        tasks = [self.scan_host(host, ports) for host in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if isinstance(r, HostResult)]

    async def _resolve_hostname(self, ip: str) -> str:
        try:
            loop = asyncio.get_event_loop()
            result = await loop.getaddrinfo(ip, None, family=socket.AF_INET)
            return result[0][3][0] if result else ""
        except (socket.gaierror, IndexError):
            return ""

    def get_summary(self) -> dict[str, Any]:
        total_hosts = len(self.results)
        total_open_ports = sum(r.open_ports for r in self.results)
        total_vulns = sum(len(r.vulnerabilities) for r in self.results)
        return {
            "total_hosts": total_hosts,
            "total_open_ports": total_open_ports,
            "total_vulnerabilities": total_vulns,
            "alerts_generated": len(self.alerts),
        }


if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    scanner = VulnScanner()
    result = asyncio.run(scanner.scan_host(target))
    import json

    print(json.dumps(result.to_dict(), indent=2))
