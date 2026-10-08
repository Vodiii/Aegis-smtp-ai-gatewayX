from types import SimpleNamespace

import pytest

from app.gateway import OriginalDeliveryTemporaryFailure, SmtpGatewayHandler
from app.domain.models import Action, Classification, GatewaySettings, PolicyDecision, ProcessingResult, ThreatCategory


class FakeRepository:
    def __init__(self):
        self.statuses = []

    def update_forward_status(self, record_id, status, error=None):
        self.statuses.append((record_id, status, error))


class FakeProcessor:
    def __init__(self):
        self.repository = FakeRepository()

    def process(self, raw):
        result = ProcessingResult(
            classification=Classification(category=ThreatCategory.BENIGN, is_threat=False, confidence=0.99),
            decision=PolicyDecision(action=Action.DELIVER, category=ThreatCategory.BENIGN, confidence=0.99),
            processing_time_ms=1,
        )
        return "r1", None, result


def test_original_delivery_failure_is_recorded(monkeypatch):
    processor = FakeProcessor()
    handler = SmtpGatewayHandler(processor, GatewaySettings())
    envelope = SimpleNamespace(content=b"Subject: x\n\nbody", rcpt_tos=["user@example.com"], mail_from="sender@example.com")

    def fail_send(*args, **kwargs):
        raise TimeoutError("smtp timeout")

    monkeypatch.setattr(handler, "_send", fail_send)

    with pytest.raises(OriginalDeliveryTemporaryFailure):
        handler._process_and_forward(envelope)

    assert processor.repository.statuses[-1][1] == "ORIGINAL_FAILED"
    assert "smtp timeout" in processor.repository.statuses[-1][2]


def test_alert_delivery_failure_is_recorded_without_raising(monkeypatch):
    processor = FakeProcessor()
    processor.process = lambda raw, delivery_key=None: (
        "r2",
        None,
        ProcessingResult(
            classification=Classification(category=ThreatCategory.TERRORISM, is_threat=True, confidence=0.95),
            decision=PolicyDecision(
                action=Action.DELIVER_AND_ALERT,
                category=ThreatCategory.TERRORISM,
                confidence=0.95,
                destination="alerts-terrorism@local.test",
            ),
            processing_time_ms=1,
        ),
    )
    handler = SmtpGatewayHandler(processor, GatewaySettings())
    envelope = SimpleNamespace(content=b"Subject: threat\n\nboom", rcpt_tos=["user@example.com"], mail_from="sender@example.com")
    calls = []

    def fake_send(*args, **kwargs):
        calls.append(kwargs.get("host"))
        if len(calls) == 1:
            return None
        raise OSError("alert unavailable")

    monkeypatch.setattr(handler, "_send", fake_send)
    _, result = handler._process_and_forward(envelope)
    assert result.decision.action == Action.DELIVER_AND_ALERT
    assert processor.repository.statuses[-1][1] == "ORIGINAL_SENT_ALERT_FAILED"
    assert "alert unavailable" in processor.repository.statuses[-1][2]
