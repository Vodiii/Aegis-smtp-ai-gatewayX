import time
from types import SimpleNamespace

from app.application.policy import PolicyEngine
from app.application.processing_service import EmailProcessor
from app.domain.models import GatewaySettings
from app.infrastructure.database.repository import MessageRepository
from app.infrastructure.queue.worker import DeliveryWorker


def test_enqueue_is_durable_and_idempotent(tmp_path):
    repo = MessageRepository(str(tmp_path / "db.sqlite"), str(tmp_path / "data"))
    raw = b"Subject: test\r\n\r\nhello\r\n"
    key = repo.make_delivery_key(raw, "sender@local.test", ["user@local.test"])
    first, created = repo.enqueue_message(raw, "sender@local.test", ["user@local.test"], key)
    second, created2 = repo.enqueue_message(raw, "sender@local.test", ["user@local.test"], key)
    assert created is True
    assert created2 is False
    assert first == second
    job = repo.find_queue_by_delivery_key(key)
    assert job is not None
    assert repo.read_spooled_message(job["raw_path"]) == raw


def test_claim_is_single_and_recover_stale(tmp_path):
    repo = MessageRepository(str(tmp_path / "db.sqlite"), str(tmp_path / "data"))
    raw = b"Subject: test\r\n\r\nhello\r\n"
    key = repo.make_delivery_key(raw, "sender@local.test", ["user@local.test"])
    job_id, _ = repo.enqueue_message(raw, "sender@local.test", ["user@local.test"], key)
    first = repo.claim_next_job()
    second = repo.claim_next_job()
    assert first["job_id"] == job_id
    assert second is None
    recovered = repo.recover_stale_jobs(0)
    assert recovered == 1
    assert repo.claim_next_job()["job_id"] == job_id


def test_delivery_state_is_per_recipient(tmp_path):
    settings = GatewaySettings(original_smtp_host="orig", original_smtp_port=1025, alert_smtp_host="alert", alert_smtp_port=1025)
    repo = MessageRepository(str(tmp_path / "db.sqlite"), str(tmp_path / "data"))
    repo.configure_delivery_endpoints(settings)
    raw = b"From: s@local.test\r\nTo: a@local.test\r\n\r\nhello\r\n"
    key = repo.make_delivery_key(raw, "s@local.test", ["a@local.test", "b@local.test"])
    job_id, _ = repo.enqueue_message(raw, "s@local.test", ["a@local.test", "b@local.test"], key)
    job = repo.claim_next_job()
    assert job["job_id"] == job_id
    # Seed a processed message row through the old repository API.
    from app.domain.models import Action, Classification, EmailDocument, PolicyDecision, ProcessingResult, ThreatCategory
    result = ProcessingResult(
        classification=Classification(category=ThreatCategory.BENIGN, is_threat=False, confidence=1.0),
        decision=PolicyDecision(action=Action.DELIVER, category=ThreatCategory.BENIGN, confidence=1.0),
        processing_time_ms=1,
    )
    repo.save("m1", raw, EmailDocument(sender="s@local.test", recipients=["a@local.test", "b@local.test"]), result, key)
    repo.ensure_delivery_records("m1", ["a@local.test", "b@local.test"], None)
    rows = repo.due_deliveries("m1")
    assert {r["recipient"] for r in rows} == {"a@local.test", "b@local.test"}
    repo.mark_delivery_sent(rows[0]["delivery_id"])
    summary = repo.delivery_summary("m1")
    assert summary["sent"] == 1
    assert summary["pending"] == 1


def _seed_message(repo, settings, tmp_path, recipients):
    from app.domain.models import Action, Classification, EmailDocument, PolicyDecision, ProcessingResult, ThreatCategory
    raw = b"From: s@local.test\r\nTo: " + ", ".join(recipients).encode() + b"\r\n\r\nhello\r\n"
    result = ProcessingResult(
        classification=Classification(category=ThreatCategory.BENIGN, is_threat=False, confidence=1.0),
        decision=PolicyDecision(action=Action.DELIVER, category=ThreatCategory.BENIGN, confidence=1.0),
        processing_time_ms=1,
    )
    email = EmailDocument(sender="s@local.test", recipients=recipients, subject="x")
    repo.save("m2", raw, email, result, repo.make_delivery_key(raw, "s@local.test", recipients))
    repo.ensure_delivery_records("m2", recipients, None)
    return raw


def test_partial_delivery_failure_isolated_per_recipient(tmp_path):
    settings = GatewaySettings(
        original_smtp_host="orig",
        original_smtp_port=1025,
        alert_smtp_host="alert",
        alert_smtp_port=1025,
        delivery_retry_base_seconds=0,
        delivery_max_attempts=8,
    )
    repo = MessageRepository(str(tmp_path / "db.sqlite"), str(tmp_path / "data"))
    repo.configure_delivery_endpoints(settings)
    _seed_message(repo, settings, tmp_path, ["a@local.test", "b@local.test"])

    processor = SimpleNamespace(repository=repo)
    worker = DeliveryWorker(repo, processor, settings)
    calls = []

    def fake_send(mail_from, recipient, raw, host, port):
        calls.append(recipient)
        if recipient == "b@local.test":
            raise TimeoutError("b unavailable")

    worker._send_one = fake_send
    job = {"job_id": "j", "attempts": 1, "sender": "s@local.test"}
    worker._deliver_due("m2", job)

    assert calls == ["a@local.test", "b@local.test"]
    rows = {r["recipient"]: r for r in repo.due_deliveries("m2")}
    # a is no longer due because it was durably marked SENT; b remains retryable.
    assert "a@local.test" not in rows
    assert rows["b@local.test"]["status"] == "RETRY"


def test_permanent_downstream_rejection_becomes_final_failure(tmp_path):
    settings = GatewaySettings(
        original_smtp_host="orig",
        original_smtp_port=1025,
        delivery_retry_base_seconds=0,
        delivery_max_attempts=8,
    )
    repo = MessageRepository(str(tmp_path / "db.sqlite"), str(tmp_path / "data"))
    repo.configure_delivery_endpoints(settings)
    _seed_message(repo, settings, tmp_path, ["a@local.test"])
    processor = SimpleNamespace(repository=repo)
    worker = DeliveryWorker(repo, processor, settings)

    def reject(*args, **kwargs):
        import smtplib
        raise smtplib.SMTPResponseException(550, "user unknown")

    worker._send_one = reject
    worker._deliver_due("m2", {"job_id": "j", "attempts": 1, "sender": "s@local.test"})
    summary = repo.delivery_summary("m2")
    assert summary["final_failed"] == 1
    assert summary["retryable"] == 0


def test_existing_sent_message_is_not_requeued_as_pending(tmp_path):
    from app.domain.models import Action, Classification, EmailDocument, PolicyDecision, ProcessingResult, ThreatCategory
    settings = GatewaySettings(original_smtp_host="orig", original_smtp_port=1025)
    repo = MessageRepository(str(tmp_path / "db.sqlite"), str(tmp_path / "data"))
    repo.configure_delivery_endpoints(settings)
    raw = b"Subject: legacy\r\n\r\nhello\r\n"
    key = repo.make_delivery_key(raw, "s@local.test", ["a@local.test"])
    result = ProcessingResult(
        classification=Classification(category=ThreatCategory.BENIGN, is_threat=False, confidence=1.0),
        decision=PolicyDecision(action=Action.DELIVER, category=ThreatCategory.BENIGN, confidence=1.0),
        processing_time_ms=1,
    )
    email = EmailDocument(sender="s@local.test", recipients=["a@local.test"])
    repo.save("legacy", raw, email, result, delivery_key=key)
    repo.update_forward_status("legacy", "ORIGINAL_SENT")
    repo.ensure_delivery_records("legacy", ["a@local.test"], None)
    rows = repo.due_deliveries("legacy")
    assert rows == []
    assert repo.delivery_summary("legacy")["sent"] == 1
