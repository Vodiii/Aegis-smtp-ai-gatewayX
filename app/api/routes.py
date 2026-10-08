from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from app.infrastructure.config import AppConfig
from app.infrastructure.database.repository import MessageRepository


def build_router(config: AppConfig, repository: MessageRepository) -> APIRouter:
    router = APIRouter(prefix="/api")

    @router.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": config.gateway.mode}

    @router.get("/messages")
    def messages(limit: int = Query(default=100, ge=1, le=500)):
        return repository.list_messages(limit)

    @router.get("/messages/{record_id}")
    def message(record_id: str):
        result = repository.get(record_id)
        if result is None:
            raise HTTPException(status_code=404, detail="Message not found")
        return result

    @router.get("/stats")
    def stats():
        result = repository.stats()
        result["queue"] = repository.queue_stats()
        result["generated_at"] = datetime.now(timezone.utc).isoformat()
        return result

    @router.get("/settings")
    def settings():
        gateway = config.gateway
        return {
            "mode": gateway.mode,
            "thresholds": {
                "TERRORISM": gateway.terrorism_threshold,
                "TECHNOGENIC": gateway.technogenic_threshold,
                "ILLEGAL": gateway.illegal_threshold,
                "OTHER_THREAT": gateway.other_threat_threshold,
            },
            "risk_engine": {
                "ai_threshold": gateway.risk_ai_threshold,
                "low_threshold": gateway.risk_low_threshold,
                "char_threshold": gateway.risk_char_threshold,
                "require_ai_on_obfuscation": gateway.risk_require_ai_on_obfuscation,
                "training_path": gateway.risk_training_path,
            },
            "destinations": {
                "TERRORISM": gateway.terrorism_destination,
                "TECHNOGENIC": gateway.technogenic_destination,
                "ILLEGAL": gateway.illegal_destination,
                "OTHER_THREAT": gateway.other_threat_destination,
            },
            "deepseek_model": gateway.deepseek_model,
            "limits": {
                "max_message_size_bytes": gateway.max_message_size_bytes,
                "max_ai_text_chars": gateway.max_ai_text_chars,
                "max_recipients": gateway.max_recipients,
                "max_attachments": gateway.max_attachments,
            },
            "allowed_recipient_domains": list(gateway.allowed_recipient_domains),
        }

    return router
