from __future__ import annotations

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
        return repository.stats()

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
            "destinations": {
                "TERRORISM": gateway.terrorism_destination,
                "TECHNOGENIC": gateway.technogenic_destination,
                "ILLEGAL": gateway.illegal_destination,
                "OTHER_THREAT": gateway.other_threat_destination,
            },
            "deepseek_model": gateway.deepseek_model,
        }

    return router
