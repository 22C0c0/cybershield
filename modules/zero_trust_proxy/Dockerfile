FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY shared/ shared/
COPY modules/zero_trust_proxy/ modules/zero_trust_proxy/

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    pydantic

EXPOSE 8005

CMD ["python", "-m", "modules.zero_trust_proxy.src.api"]
