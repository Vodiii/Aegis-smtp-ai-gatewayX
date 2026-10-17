from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from app.application.emergency_calls import (
    EmergencyCallService,
    EmergencyMessageNotFound,
    EmergencyServiceNotFound,
    MessageIsNotThreat,
)
from app.infrastructure.config import AppConfig
from app.infrastructure.database.repository import MessageRepository


class EmergencyCallRequest(BaseModel):
    service_id: str = Field(min_length=1, max_length=80, description="ID from GET /api/emergency-services")
    requested_by: str | None = Field(default=None, max_length=120, description="Optional operator name or ID")
    notes: str | None = Field(default=None, max_length=1000, description="Optional note for the audit log")


def build_router(config: AppConfig, repository: MessageRepository) -> APIRouter:
    router = APIRouter(prefix="/api")
    emergency_calls = EmergencyCallService(repository)

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

    @router.get("/emergency-services")
    def list_emergency_services():
        """Вернуть каталог тестовых служб для выпадающего списка интерфейса."""
        return emergency_calls.list_services()

    @router.post(
        "/messages/{record_id}/emergency-calls",
        status_code=status.HTTP_201_CREATED,
    )
    def create_emergency_call(record_id: str, payload: EmergencyCallRequest):
        """Записать имитацию вызова. Этот endpoint никогда не выполняет реальный звонок."""
        try:
            return emergency_calls.request_call(
                message_id=record_id,
                service_id=payload.service_id,
                requested_by=payload.requested_by,
                notes=payload.notes,
            )
        except EmergencyMessageNotFound:
            raise HTTPException(status_code=404, detail="Message not found")
        except MessageIsNotThreat:
            raise HTTPException(
                status_code=409,
                detail="Emergency-service calls can only be requested for messages classified as threats",
            )
        except EmergencyServiceNotFound:
            raise HTTPException(status_code=422, detail="Unknown emergency service ID")

    @router.get("/messages/{record_id}/emergency-calls")
    def list_emergency_calls(record_id: str):
        """Вернуть сохранённую историю имитаций вызова для одного сообщения."""
        try:
            return {
                "message_id": record_id,
                "mode": "MOCK",
                "real_calls_enabled": False,
                "items": emergency_calls.list_requests(record_id),
            }
        except EmergencyMessageNotFound:
            raise HTTPException(status_code=404, detail="Message not found")

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
            "emergency_calls": {
                "mode": "MOCK",
                "real_calls_enabled": False,
            },
        }

    return router
