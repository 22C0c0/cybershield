"""Vulnerability Scanner API — REST interface."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CyberShield Vulnerability Scanner", version="1.0.0")


class ScanRequest(BaseModel):
    target: str
    ports: list[int] | None = None
    network_scan: bool = False


@app.get("/health")
async def health():
    return {"status": "healthy", "module": "vuln-scanner"}


@app.post("/api/v1/scan")
async def scan_target(request: ScanRequest):
    from modules.vuln_scanner.src.engine import VulnScanner

    scanner = VulnScanner()
    if request.network_scan:
        results = await scanner.scan_network(request.target, request.ports)
        return {"hosts": [r.to_dict() for r in results], "summary": scanner.get_summary()}
    result = await scanner.scan_host(request.target, request.ports)
    return {"host": result.to_dict(), "summary": scanner.get_summary()}


@app.get("/api/v1/cves")
async def list_cves():
    from modules.vuln_scanner.src.engine import CVE_DATABASE

    return CVE_DATABASE


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8003)
