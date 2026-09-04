FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY shared/ shared/
COPY modules/vuln_scanner/ modules/vuln_scanner/

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    pydantic

EXPOSE 8003

CMD ["python", "-m", "modules.vuln_scanner.src.api"]
