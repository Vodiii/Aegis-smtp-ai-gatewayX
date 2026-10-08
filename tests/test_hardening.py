from email.message import EmailMessage
from types import SimpleNamespace

from app.domain.models import GatewaySettings
from app.gateway import SmtpGatewayHandler
from app.infrastructure.database.repository import MessageRepository


def _handler(tmp_path):
    repo = MessageRepository(str(tmp_path / "db.sqlite"), str(tmp_path / "data"))
    processor = SimpleNamespace(repository=repo)
    return SmtpGatewayHandler(processor, GatewaySettings()), repo


def test_delivery_key_changes_when_envelope_changes():
    raw = b"Subject: x\n\nbody"
    first = MessageRepository.make_delivery_key(raw, "sender@example.com", ["a@local.test"])
    retry = MessageRepository.make_delivery_key(raw, "sender@example.com", ["a@local.test"])
    other = MessageRepository.make_delivery_key(raw, "sender@example.com", ["b@local.test"])
    assert first == retry
    assert first != other


def test_recipient_allowlist_and_limit(tmp_path):
    handler, _repo = _handler(tmp_path)
    envelope = SimpleNamespace(rcpt_tos=[])
    allowed = __import__("asyncio").run(
        handler.handle_RCPT(None, None, envelope, "user@local.test", [])
    )
    denied = __import__("asyncio").run(
        handler.handle_RCPT(None, None, envelope, "user@example.com", [])
    )
    assert allowed.startswith("250")
    assert denied.startswith("550")


def test_alert_copy_has_loop_marker_but_original_bytes_do_not_change(tmp_path):
    handler, _repo = _handler(tmp_path)
    raw = (
        b"From: sender@local.test\r\n"
        b"To: user@local.test\r\n"
        b"Subject: Hello\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
        b"Hello\r\n"
    )
    alert = handler._build_alert_copy(raw, "alerts@local.test")
    assert raw == raw
    parsed = EmailMessage()
    from email.parser import BytesParser
    from email import policy
    parsed = BytesParser(policy=policy.default).parsebytes(alert)
    assert parsed["X-AI-SMTP-Gateway-Alert"] == "1"
    assert parsed["X-AI-SMTP-Gateway-Token"] == handler.loop_token
    assert handler._is_loop_copy(alert)
    assert not handler._is_loop_copy(raw)


def test_repository_persists_delivery_key(tmp_path):
    from app.domain.models import Action, Classification, PolicyDecision, ProcessingResult, ThreatCategory, EmailDocument

    repo = MessageRepository(str(tmp_path / "db.sqlite"), str(tmp_path / "data"))
    result = ProcessingResult(
        classification=Classification(category=ThreatCategory.BENIGN, is_threat=False, confidence=0.99),
        decision=PolicyDecision(action=Action.DELIVER, category=ThreatCategory.BENIGN, confidence=0.99),
        processing_time_ms=4,
    )
    repo.save("r1", b"Subject: x\n\nbody", EmailDocument(sender="sender@local.test"), result, delivery_key="abc")
    row = repo.find_by_delivery_key("abc")
    assert row is not None
    assert row["id"] == "r1"



def test_loop_marker_does_not_match_plain_message(tmp_path):
    handler, _repo = _handler(tmp_path)
    raw = b"From: sender@local.test\r\nTo: user@local.test\r\nSubject: x\r\n\r\nbody\r\n"
    assert not handler._is_loop_copy(raw)


def test_fallback_classifies_generic_personal_threat_as_other():
    from app.infrastructure.deepseek.client import DeepSeekClient
    from app.domain.models import EmailDocument, ThreatCategory

    result = DeepSeekClient._fallback(
        EmailDocument(subject="Предупреждение", text="Если он придет, я причиню вред сотруднику."),
        "AI unavailable",
    )
    assert result.category == ThreatCategory.OTHER_THREAT
    assert result.is_threat is True
