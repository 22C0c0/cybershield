"""Background worker threads for long-running CyberShield operations.

Runs blocking engine calls off the GUI thread so the UI stays responsive.
"""

from __future__ import annotations

import asyncio
import threading
from typing import TYPE_CHECKING, Any

from PySide6.QtCore import QThread, Signal

if TYPE_CHECKING:
    from collections.abc import Callable


class Worker(QThread):
    """Runs a blocking callable in a worker thread, emits the result."""

    finished = Signal(object)
    failed = Signal(str)

    def __init__(self, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
        super().__init__()
        self._fn = fn
        self._args = args
        self._kwargs = kwargs

    def run(self) -> None:  # noqa: D102
        try:
            self.finished.emit(self._fn(*self._args, **self._kwargs))
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class AsyncWorker(Worker):
    """Runs an async callable via asyncio.run in a worker thread."""

    def run(self) -> None:
        try:
            self.finished.emit(asyncio.run(self._fn(*self._args, **self._kwargs)))
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            self.failed.emit(f"{type(exc).__name__}: {exc}")


class CaptureWorker(QThread):
    """Runs NIDS packet capture until stopped, then emits the alert list."""

    finished = Signal(list)
    failed = Signal(str)

    def __init__(self, engine: Any, interface: str, packet_count: int = 0) -> None:
        super().__init__()
        self._engine = engine
        self._interface = interface
        self._packet_count = packet_count
        self._stop_event = threading.Event()

    def run(self) -> None:
        try:
            from scapy.all import sniff

            def _should_stop(_packet: Any) -> bool:
                return self._stop_event.is_set()

            sniff(
                iface=self._interface,
                prn=self._engine._process_packet,  # noqa: SLF001 - scapy callback by design
                count=self._packet_count,
                stop_filter=_should_stop,
                store=False,
            )
            self.finished.emit(list(self._engine.alerts))
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            self.failed.emit(f"{type(exc).__name__}: {exc}")

    def stop(self) -> None:
        self._stop_event.set()
