from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api.routes import build_router
from app.domain.models import (
    Action,
    Classification,
    EmailDocument,
    GatewaySettings,
    PolicyDecision,
    ProcessingResult,
    ThreatCategory,
)
from app.infrastructure.config import AppConfig
from app.infrastructure.database.repository import MessageRepository


def _client_with_repository(tmp_path):
    settings = GatewaySettings(
        db_path=str(tmp_path / "gateway.db"),
        data_dir=str(tmp_path / "data"),
    )
    repository = MessageRepository(settings.db_path, settings.data_dir)
    config = AppConfig(
        gateway=settings,
        deepseek_primary_key=None,
        deepseek_secondary_key=None,
    )
    app = FastAPI()
    app.include_router(build_router(config, repository))
    return TestClient(app), repository


def _save_message(repository, *, record_id: str, is_threat: bool) -> None:
    category = ThreatCategory.TERRORISM if is_threat else ThreatCategory.BENIGN
    action = Action.DELIVER_AND_ALERT if is_threat else Action.DELIVER
    result = ProcessingResult(
        classification=Classification(
            category=category,
            is_threat=is_threat,
            confidence=0.95 if is_threat else 0.99,
            reason="test fixture",
        ),
        decision=PolicyDecision(
            action=action,
            category=category,
            confidence=0.95 if is_threat else 0.99,
            destination="alerts-terrorism@local.test" if is_threat else None,
        ),
        processing_time_ms=1,
    )
    email = EmailDocument(
        sender="sender@local.test",
        recipients=["recipient@local.test"],
        subject="Test threat" if is_threat else "Ordinary message",
        text="Test body",
    )
    repository.save(record_id, b"Subject: test\r\n\r\nTest body\r\n", email, result)


def test_emergency_service_catalog_is_mock_only(tmp_path):
    client, _ = _client_with_repository(tmp_path)

    response = client.get("/api/emergency-services")

    assert response.status_code == 200
    payload = response.json()
    assert payload["mode"] == "MOCK"
    assert payload["real_calls_enabled"] is False
    assert len(payload["services"]) == 4
    assert all(service["mock_only"] is True for service in payload["services"])
    assert all(service["number"].startswith("TEST-") for service in payload["services"])


def test_threat_message_creates_persisted_simulated_call(tmp_path):
    client, repository = _client_with_repository(tmp_path)
    _save_message(repository, record_id="threat-1", is_threat=True)

    response = client.post(
        "/api/messages/threat-1/emergency-calls",
        json={"service_id": "police", "requested_by": "operator-1", "notes": "Demo action"},
    )

    assert response.status_code == 201
    payload = response.json()
    assert payload["message_id"] == "threat-1"
    assert payload["service_id"] == "police"
    assert payload["service_number"] == "TEST-101"
    assert payload["provider"] == "MOCK"
    assert payload["status"] == "SIMULATED"
    assert payload["real_call_placed"] is False
    assert payload["requested_by"] == "operator-1"
    assert payload["notes"] == "Demo action"

    history = client.get("/api/messages/threat-1/emergency-calls")
    assert history.status_code == 200
    history_payload = history.json()
    assert history_payload["real_calls_enabled"] is False
    assert len(history_payload["items"]) == 1
    assert history_payload["items"][0]["id"] == payload["id"]


def test_benign_message_cannot_request_emergency_call(tmp_path):
    client, repository = _client_with_repository(tmp_path)
    _save_message(repository, record_id="benign-1", is_threat=False)

    response = client.post(
        "/api/messages/benign-1/emergency-calls",
        json={"service_id": "police"},
    )

    assert response.status_code == 409
    assert client.get("/api/messages/benign-1/emergency-calls").json()["items"] == []


def test_emergency_call_api_validates_message_and_service(tmp_path):
    client, repository = _client_with_repository(tmp_path)
    _save_message(repository, record_id="threat-2", is_threat=True)

    missing_message = client.post(
        "/api/messages/missing/emergency-calls", json={"service_id": "police"}
    )
    unknown_service = client.post(
        "/api/messages/threat-2/emergency-calls", json={"service_id": "unknown-service"}
    )

    assert missing_message.status_code == 404
    assert unknown_service.status_code == 422


def test_emergency_call_history_survives_repository_restart(tmp_path):
    client, repository = _client_with_repository(tmp_path)
    _save_message(repository, record_id="threat-3", is_threat=True)
    response = client.post(
        "/api/messages/threat-3/emergency-calls", json={"service_id": "security_service"}
    )
    assert response.status_code == 201

    restarted_repository = MessageRepository(repository.db_path, str(tmp_path / "data"))
    restarted_config = AppConfig(
        gateway=GatewaySettings(),
        deepseek_primary_key=None,
        deepseek_secondary_key=None,
    )
    app = FastAPI()
    app.include_router(build_router(restarted_config, restarted_repository))
    with TestClient(app) as restarted_client:
        history = restarted_client.get("/api/messages/threat-3/emergency-calls")

    assert history.status_code == 200
    assert len(history.json()["items"]) == 1
    assert history.json()["items"][0]["provider"] == "MOCK"
