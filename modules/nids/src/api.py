"""CyberShield NIDS API — REST interface for the detection engine."""

from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="CyberShield NIDS", version="1.0.0")


class ScanRequest(BaseModel):
    interface: str = "eth0"
    packet_count: int = 1000


class AlertResponse(BaseModel):
    id: str
    module: str
    title: str
    description: str
    severity: str
    source_ip: str
    destination_ip: str
    timestamp: str
    tags: list[str]


@app.get("/health")
async def health():
    return {"status": "healthy", "module": "nids"}


@app.get("/api/v1/stats")
async def get_stats():
    from modules.nids.src.engine import NIDSEngine
    engine = NIDSEngine()
    return engine.get_stats()


@app.post("/api/v1/scan")
async def start_scan(request: ScanRequest):
    return {
        "status": "started",
        "interface": request.interface,
        "message": "Packet capture initiated",
    }


@app.get("/api/v1/signatures")
async def list_signatures():
    from modules.nids.src.engine import SignatureEngine
    engine = SignatureEngine()
    return [
        {"name": s.name, "severity": s.severity.value, "tags": s.tags}
        for s in engine.signatures
    ]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
