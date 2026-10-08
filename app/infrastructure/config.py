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


def _domains(name: str, default: str) -> tuple[str, ...]:
    raw = os.getenv(name, default)
    return tuple(item.strip().lower() for item in raw.split(",") if item.strip())


def load_config() -> AppConfig:
    gateway = GatewaySettings(
        original_smtp_host=os.getenv("ORIGINAL_SMTP_HOST", "mailpit-original"),
        original_smtp_port=_int("ORIGINAL_SMTP_PORT", 1025),
        alert_smtp_host=os.getenv("ALERT_SMTP_HOST", "mailpit-alert"),
        alert_smtp_port=_int("ALERT_SMTP_PORT", 1025),
        smtp_timeout_seconds=_float("SMTP_TIMEOUT_SECONDS", 8.0),
        deepseek_model=os.getenv("DEEPSEEK_MODEL", "deepseek-flash"),
        deepseek_api_timeout_seconds=_float("DEEPSEEK_API_TIMEOUT_SECONDS", 8.0),
        deepseek_max_retries=_int("DEEPSEEK_MAX_RETRIES", 1),
        deepseek_retry_backoff_seconds=_float("DEEPSEEK_RETRY_BACKOFF_SECONDS", 0.35),
        max_ai_text_chars=_int("MAX_AI_TEXT_CHARS", 6000),
        max_message_size_bytes=_int("MAX_MESSAGE_SIZE_BYTES", 10 * 1024 * 1024),
        max_recipients=_int("MAX_RECIPIENTS", 50),
        max_attachments=_int("MAX_ATTACHMENTS", 20),
        allowed_recipient_domains=_domains("ALLOWED_RECIPIENT_DOMAINS", "local.test"),
        gateway_loop_token=os.getenv("GATEWAY_LOOP_TOKEN", ""),
        data_dir=os.getenv("DATA_DIR", "./data"),
        db_path=os.getenv("DB_PATH", "./data/gateway.db"),
        mode=os.getenv("GATEWAY_MODE", "ENFORCE").upper(),
        terrorism_threshold=_float("THRESHOLD_TERRORISM", 0.70),
        technogenic_threshold=_float("THRESHOLD_TECHNOGENIC", 0.60),
        illegal_threshold=_float("THRESHOLD_ILLEGAL", 0.80),
        other_threat_threshold=_float("THRESHOLD_OTHER_THREAT", 0.75),
        terrorism_destination=os.getenv("DESTINATION_TERRORISM", "alerts-terrorism@local.test"),
        technogenic_destination=os.getenv("DESTINATION_TECHNOGENIC", "alerts-technogenic@local.test"),
        illegal_destination=os.getenv("DESTINATION_ILLEGAL", "alerts-illegal@local.test"),
        other_threat_destination=os.getenv("DESTINATION_OTHER_THREAT", "alerts-other@local.test"),
        risk_ai_threshold=_float("RISK_AI_THRESHOLD", 0.22),
        risk_low_threshold=_float("RISK_LOW_THRESHOLD", 0.08),
        risk_char_threshold=_float("RISK_CHAR_THRESHOLD", 0.75),
        risk_require_ai_on_obfuscation=os.getenv("RISK_REQUIRE_AI_ON_OBFUSCATION", "true").lower() in {"1", "true", "yes", "on"},
        risk_training_path=os.getenv("RISK_TRAINING_PATH", "./config/risk_training.json"),
    )
    return AppConfig(
        gateway=gateway,
        deepseek_primary_key=os.getenv("DEEPSEEK_API_KEY_PRIMARY"),
        deepseek_secondary_key=os.getenv("DEEPSEEK_API_KEY_SECONDARY"),
    )
