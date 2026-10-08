from types import SimpleNamespace

import pytest

from app.gateway import SmtpGatewayHandler
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

    with pytest.raises(TimeoutError):
        handler._process_and_forward(envelope)

    assert processor.repository.statuses[-1][1] == "ORIGINAL_FAILED"
    assert "smtp timeout" in processor.repository.statuses[-1][2]
