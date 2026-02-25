from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = "Train-Ticket Graph API"
    app_version: str = "1.0.0"
    app_description: str = "Query engine for the Train-Ticket microservice dependency graph."

    data_file: Path = Path(__file__).parent.parent.parent.parent.parent / "data" / "train-ticket.json"

    host: str = "0.0.0.0"
    port: int = 8080

    log_level: str = "info"

    model_config = {"env_prefix": "APP_", "env_file": ".env", "env_file_encoding": "utf-8"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
