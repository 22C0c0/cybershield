"""Centralized configuration loader."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(key: str, default: str = "") -> str:
    return os.getenv(key, default)


@dataclass(frozen=True)
class DatabaseConfig:
    host: str = field(default_factory=lambda: _env("POSTGRES_HOST", "localhost"))
    port: int = field(default_factory=lambda: int(_env("POSTGRES_PORT", "5432")))
    name: str = field(default_factory=lambda: _env("POSTGRES_DB", "cybershield"))
    user: str = field(default_factory=lambda: _env("POSTGRES_USER", "cybershield"))
    password: str = field(default_factory=lambda: _env("POSTGRES_PASSWORD", ""))

    @property
    def url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"
        )


@dataclass(frozen=True)
class RedisConfig:
    host: str = field(default_factory=lambda: _env("REDIS_HOST", "localhost"))
    port: int = field(default_factory=lambda: int(_env("REDIS_PORT", "6379")))

    @property
    def url(self) -> str:
        return f"redis://{self.host}:{self.port}/0"


@dataclass(frozen=True)
class ClickHouseConfig:
    host: str = field(default_factory=lambda: _env("CLICKHOUSE_HOST", "localhost"))
    port: int = field(default_factory=lambda: int(_env("CLICKHOUSE_PORT", "8123")))


@dataclass(frozen=True)
class KafkaConfig:
    broker: str = field(default_factory=lambda: _env("KAFKA_BROKER", "localhost:9092"))
    topic_alerts: str = field(
        default_factory=lambda: _env("KAFKA_TOPIC_ALERTS", "cybershield.alerts")
    )
    topic_logs: str = field(default_factory=lambda: _env("KAFKA_TOPIC_LOGS", "cybershield.logs"))


@dataclass(frozen=True)
class AppConfig:
    name: str = field(default_factory=lambda: _env("APP_NAME", "cybershield"))
    log_level: str = field(default_factory=lambda: _env("LOG_LEVEL", "INFO"))
    secret_key: str = field(default_factory=lambda: _env("SECRET_KEY", "dev-secret"))
    base_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent)

    db: DatabaseConfig = field(default_factory=DatabaseConfig)
    redis: RedisConfig = field(default_factory=RedisConfig)
    clickhouse: ClickHouseConfig = field(default_factory=ClickHouseConfig)
    kafka: KafkaConfig = field(default_factory=KafkaConfig)


def load_config() -> AppConfig:
    """Load configuration from environment variables."""
    return AppConfig()
