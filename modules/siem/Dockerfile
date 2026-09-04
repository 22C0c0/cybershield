FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml .
COPY shared/ shared/
COPY modules/siem/ modules/siem/

RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    pydantic

EXPOSE 8004

CMD ["python", "-m", "modules.siem.src.api"]
