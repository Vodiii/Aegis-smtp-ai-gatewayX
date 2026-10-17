from __future__ import annotations

from datetime import datetime, timezone
import uuid
from typing import Any

from app.infrastructure.database.repository import MessageRepository


# Используются специально фиктивные номера, по которым нельзя позвонить.
# Функция работает только в режиме имитации и не подключается к телефонной сети или провайдеру связи.
MOCK_EMERGENCY_SERVICES: tuple[dict[str, Any], ...] = (
    {
        "id": "police",
        "name": "Полиция (демо)",
        "number": "TEST-101",
        "description": "Тестовый контакт полиции. Реальный вызов не выполняется.",
        "mock_only": True,
    },
    {
        "id": "fire_rescue",
        "name": "Пожарно-спасательная служба (демо)",
        "number": "TEST-102",
        "description": "Тестовый контакт пожарно-спасательной службы. Реальный вызов не выполняется.",
        "mock_only": True,
    },
    {
        "id": "medical_emergency",
        "name": "Скорая медицинская помощь (демо)",
        "number": "TEST-103",
        "description": "Тестовый контакт медицинской службы. Реальный вызов не выполняется.",
        "mock_only": True,
    },
    {
        "id": "security_service",
        "name": "Служба безопасности (демо)",
        "number": "TEST-104",
        "description": "Тестовый контакт службы безопасности. Реальный вызов не выполняется.",
        "mock_only": True,
    },
)


class EmergencyServiceError(Exception):
    """Базовый класс ожидаемых ошибок API имитации вызова экстренных служб."""


class EmergencyMessageNotFound(EmergencyServiceError):
    pass


class MessageIsNotThreat(EmergencyServiceError):
    pass


class EmergencyServiceNotFound(EmergencyServiceError):
    pass


class MockEmergencyCallProvider:
    """Имитировать запрос вызова без набора номера и сетевых запросов."""

    provider_name = "MOCK"

    def submit(self, service: dict[str, Any]) -> dict[str, Any]:
        return {
            "provider": self.provider_name,
            "status": "SIMULATED",
            "provider_reference": f"MOCK-{uuid.uuid4().hex[:12].upper()}",
            "real_call_placed": False,
            "provider_message": "Mock call recorded; no real telephone call was placed.",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }


class EmergencyCallService:
    def __init__(
        self,
        repository: MessageRepository,
        provider: MockEmergencyCallProvider | None = None,
    ) -> None:
        self.repository = repository
        self.provider = provider or MockEmergencyCallProvider()
        self._services = {service["id"]: service for service in MOCK_EMERGENCY_SERVICES}

    def list_services(self) -> dict[str, Any]:
        return {
            "mode": "MOCK",
            "real_calls_enabled": False,
            "services": [dict(item) for item in MOCK_EMERGENCY_SERVICES],
        }

    def request_call(
        self,
        message_id: str,
        service_id: str,
        requested_by: str | None = None,
        notes: str | None = None,
    ) -> dict[str, Any]:
        message = self.repository.get(message_id)
        if message is None:
            raise EmergencyMessageNotFound(message_id)
        if not message["is_threat"] or message["category"] == "BENIGN":
            raise MessageIsNotThreat(message_id)

        service = self._services.get(service_id)
        if service is None:
            raise EmergencyServiceNotFound(service_id)

        provider_result = self.provider.submit(service)
        return self.repository.create_emergency_call_request(
            message_id=message_id,
            service_id=service["id"],
            service_name=service["name"],
            service_number=service["number"],
            provider=provider_result["provider"],
            provider_reference=provider_result["provider_reference"],
            status=provider_result["status"],
            requested_by=(requested_by or "").strip() or None,
            notes=(notes or "").strip() or None,
            created_at=provider_result["created_at"],
            real_call_placed=provider_result["real_call_placed"],
            provider_message=provider_result["provider_message"],
        )

    def list_requests(self, message_id: str) -> list[dict[str, Any]]:
        if self.repository.get(message_id) is None:
            raise EmergencyMessageNotFound(message_id)
        return self.repository.list_emergency_call_requests(message_id)
