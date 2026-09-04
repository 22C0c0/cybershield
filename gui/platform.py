"""Cross-platform helpers for the CyberShield GUI."""

from __future__ import annotations

import os
import socket
import sys


def detect_interface() -> str:
    """Return the most likely default network interface for this platform.

    Falls back to a per-OS default ('eth0' Linux, 'en0' macOS, '' Windows)
    when no active interface can be auto-detected.
    """
    for name in _candidate_interfaces():
        if name:
            return name
    if sys.platform == "darwin":
        return "en0"
    if os.name == "nt":
        return ""
    return "eth0"


def _candidate_interfaces() -> list[str]:
    candidates: list[str] = []
    try:
        import scapy.all as scapy  # type: ignore[import-not-found]

        for iface in scapy.conf.ifaces.values():
            iface_name = iface.name
            if iface_name in {"lo", "lo0", "Loopback"} or iface_name.startswith(
                ("docker", "veth", "br-", "vmnet")
            ):
                continue
            candidates.append(iface_name)
    except Exception:  # noqa: BLE001,S110 - scapy may be unavailable; UDP fallback below
        pass

    candidates.extend(_udp_route_interface())
    return candidates


def _udp_route_interface() -> list[str]:
    """Pick the interface used by the default route (no packets sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return [sock.getsockname()[0]]
    except (OSError, KeyError):
        return []


def platform_name() -> str:
    return {"win32": "Windows", "darwin": "macOS"}.get(sys.platform, sys.platform)


def requires_admin_hint() -> str:
    if os.name == "nt":
        return "Run the app as Administrator for packet capture."
    if sys.platform == "darwin":
        return "Packet capture may require sudo / root privileges."
    return "Packet capture requires root or CAP_NET_RAW (see README)."
