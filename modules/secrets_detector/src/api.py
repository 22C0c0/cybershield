"""Secrets Detector API — REST interface."""

from __future__ import annotations

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="CyberShield Secrets Detector", version="1.0.0")


class ScanRequest(BaseModel):
    path: str = "."
    max_depth: int = 10


class ContentScanRequest(BaseModel):
    content: str
    source: str = "inline"


@app.get("/health")
async def health():
    return {"status": "healthy", "module": "secrets-detector"}


@app.post("/api/v1/scan")
async def scan_directory(request: ScanRequest):
    from modules.secrets_detector.src.engine import SecretsDetector
    from pathlib import Path

    detector = SecretsDetector()
    detector.scan_directory(Path(request.path), request.max_depth)
    return detector.generate_report()


@app.post("/api/v1/scan/content")
async def scan_content(request: ContentScanRequest):
    from modules.secrets_detector.src.engine import SecretsDetector

    detector = SecretsDetector()
    findings = detector.scan_content(request.content, request.source)
    return {
        "total_findings": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


@app.get("/api/v1/patterns")
async def list_patterns():
    from modules.secrets_detector.src.engine import SecretPatterns

    patterns = SecretPatterns.get_default_patterns()
    return [
        {"name": p.name, "severity": p.severity.value, "tags": p.tags}
        for p in patterns
    ]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8006)
