FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY shared/ shared/
COPY modules/secrets_detector/ modules/secrets_detector/

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    pydantic

EXPOSE 8006

CMD ["python", "-m", "modules.secrets_detector.src.api"]
