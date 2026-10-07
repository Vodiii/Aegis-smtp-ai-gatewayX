from __future__ import annotations

import os
from dataclasses import dataclass

from app.domain.models import GatewaySettings


@dataclass(frozen=True)
class AppConfig:
    gateway: GatewaySettings
    deepseek_primary_key: str | None
    deepseek_secondary_key: str | None


def _float(name: str, default: float) -> float:
    raw = os.getenv(name)
    return float(raw) if raw is not None else default


def _int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw is not None else default


def load_config() -> AppConfig:
    gateway = GatewaySettings(
        original_smtp_host=os.getenv("ORIGINAL_SMTP_HOST", "mailpit-original"),
        original_smtp_port=_int("ORIGINAL_SMTP_PORT", 1025),
        alert_smtp_host=os.getenv("ALERT_SMTP_HOST", "mailpit-alert"),
        alert_smtp_port=_int("ALERT_SMTP_PORT", 1026),
        smtp_timeout_seconds=_float("SMTP_TIMEOUT_SECONDS", 8.0),
        deepseek_model=os.getenv("DEEPSEEK_MODEL", "deepseek-flash"),
        deepseek_api_timeout_seconds=_float("DEEPSEEK_API_TIMEOUT_SECONDS", 8.0),
        max_ai_text_chars=_int("MAX_AI_TEXT_CHARS", 6000),
        data_dir=os.getenv("DATA_DIR", "./data"),
        db_path=os.getenv("DB_PATH", "./data/gateway.db"),
        mode=os.getenv("GATEWAY_MODE", "ENFORCE").upper(),
        terrorism_threshold=_float("THRESHOLD_TERRORISM", 0.80),
        technogenic_threshold=_float("THRESHOLD_TECHNOGENIC", 0.80),
        illegal_threshold=_float("THRESHOLD_ILLEGAL", 0.80),
        other_threat_threshold=_float("THRESHOLD_OTHER_THREAT", 0.75),
        terrorism_destination=os.getenv("DESTINATION_TERRORISM", "alerts-terrorism@local.test"),
        technogenic_destination=os.getenv("DESTINATION_TECHNOGENIC", "alerts-technogenic@local.test"),
        illegal_destination=os.getenv("DESTINATION_ILLEGAL", "alerts-illegal@local.test"),
        other_threat_destination=os.getenv("DESTINATION_OTHER_THREAT", "alerts-other@local.test"),
    )
    return AppConfig(
        gateway=gateway,
        deepseek_primary_key=os.getenv("DEEPSEEK_API_KEY_PRIMARY"),
        deepseek_secondary_key=os.getenv("DEEPSEEK_API_KEY_SECONDARY"),
    )
