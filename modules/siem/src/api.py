"""SIEM API — REST interface for log management and alerting."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CyberShield SIEM", version="1.0.0")


class LogIngestRequest(BaseModel):
    logs: list[str]
    source: str = "api"


class AlertQuery(BaseModel):
    severity: str | None = None
    status: str | None = None
    source_ip: str | None = None
    limit: int = 100


@app.get("/health")
async def health():
    return {"status": "healthy", "module": "siem"}


@app.post("/api/v1/ingest")
async def ingest_logs(request: LogIngestRequest):
    from modules.siem.src.engine import SIEMEngine

    engine = SIEMEngine()
    alerts = engine.ingest_batch(request.logs, request.source)
    return {
        "logs_processed": len(request.logs),
        "alerts_generated": len(alerts),
        "alerts": [a.to_dict() for a in alerts],
    }


@app.get("/api/v1/alerts")
async def get_alerts(limit: int = 100):
    from modules.siem.src.engine import SIEMEngine

    engine = SIEMEngine()
    alerts = engine.alert_store.get_alerts(limit=limit)
    return [a.to_dict() for a in alerts]


@app.get("/api/v1/stats")
async def get_stats():
    from modules.siem.src.engine import SIEMEngine

    engine = SIEMEngine()
    return engine.get_stats()


@app.get("/api/v1/rules")
async def list_rules():
    from modules.siem.src.engine import SIEMEngine

    engine = SIEMEngine()
    return [
        {"name": r.name, "severity": r.severity.value, "tags": r.tags}
        for r in engine.detection.rules
    ]


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8004)
