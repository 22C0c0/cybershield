FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY shared/ shared/
COPY modules/nids/ modules/nids/

RUN pip install --no-cache-dir \
    scapy \
    fastapi \
    uvicorn[standard] \
    pydantic

EXPOSE 8001

CMD ["python", "-m", "modules.nids.src.api"]
