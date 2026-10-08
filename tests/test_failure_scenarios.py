from __future__ import annotations

import threading
from types import SimpleNamespace

import pytest

from app.domain.models import Action, Classification, EmailDocument, GatewaySettings, PolicyDecision, ProcessingResult, ThreatCategory
from app.infrastructure.database.repository import MessageRepository
from app.infrastructure.queue.worker import DeliveryWorker


def _seed_message(repo: MessageRepository, recipients: list[str], *, alert: str | None = None) -> str:
    raw = b"From: sender@local.test\r\nTo: " + ", ".join(recipients).encode() + b"\r\nSubject: test\r\n\r\nhello\r\n"
    result = ProcessingResult(
        classification=Classification(
            category=ThreatCategory.TERRORISM if alert else ThreatCategory.BENIGN,
            is_threat=bool(alert),
            confidence=0.95,
        ),
        decision=PolicyDecision(
            action=Action.DELIVER_AND_ALERT if alert else Action.DELIVER,
            category=ThreatCategory.TERRORISM if alert else ThreatCategory.BENIGN,
            confidence=0.95,
            destination=alert,
        ),
        processing_time_ms=1,
    )
    message_id = "m-" + ("alert" if alert else "plain")
    repo.save(
        message_id,
        raw,
        EmailDocument(sender="sender@local.test", recipients=recipients, subject="test"),
        result,
        repo.make_delivery_key(raw, "sender@local.test", recipients),
    )
    repo.ensure_delivery_records(message_id, recipients, alert)
    return message_id


def _settings() -> GatewaySettings:
    return GatewaySettings(
        original_smtp_host="orig",
        original_smtp_port=1025,
        alert_smtp_host="alert",
        alert_smtp_port=1025,
        queue_retry_base_seconds=0,
        queue_retry_max_seconds=0,
        delivery_retry_base_seconds=0,
        delivery_max_attempts=3,
    )


def test_duplicate_enqueue_is_atomic_under_concurrency(tmp_path):
    repo = MessageRepository(str(tmp_path / "db.sqlite"), str(tmp_path / "data"))
    raw = b"Subject: duplicate\r\n\r\nhello\r\n"
    key = repo.make_delivery_key(raw, "sender@local.test", ["user@local.test"])
    results: list[tuple[str, bool]] = []
    errors: list[Exception] = []

    def submit() -> None:
        try:
            results.append(repo.enqueue_message(raw, "sender@local.test", ["user@local.test"], key))
        except Exception as exc:  # pragma: no cover - safety assertion
            errors.append(exc)

    threads = [threading.Thread(target=submit) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 8
    assert len({job_id for job_id, _created in results}) == 1
    assert sum(created for _job_id, created in results) == 1
    with repo._connect() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM queue_jobs").fetchone()["c"] == 1


def test_partial_recipient_failure_does_not_retry_already_sent_recipient(tmp_path):
    repo = MessageRepository(str(tmp_path / "db.sqlite"), str(tmp_path / "data"))
    message_id = _seed_message(repo, ["ok@local.test", "retry@local.test"])
    worker = DeliveryWorker(repo, SimpleNamespace(repository=repo), _settings())
    sent: list[str] = []

    def send_one(_sender: str, recipient: str, _raw: bytes, _host: str, _port: int) -> None:
        sent.append(recipient)
        if recipient == "retry@local.test":
            raise TimeoutError("temporary downstream failure")

    worker._send_one = send_one
    worker._deliver_due(message_id, {"sender": "sender@local.test", "attempts": 1, "job_id": "job"})

    assert sent == ["ok@local.test", "retry@local.test"]
    rows = repo.due_deliveries(message_id)
    assert {row["recipient"] for row in rows} == {"retry@local.test"}
    assert repo.delivery_summary(message_id)["sent"] == 1


def test_stale_processing_job_is_recovered_after_restart(tmp_path):
    repo = MessageRepository(str(tmp_path / "db.sqlite"), str(tmp_path / "data"))
    raw = b"Subject: recover\r\n\r\nhello\r\n"
    key = repo.make_delivery_key(raw, "sender@local.test", ["user@local.test"])
    job_id, _ = repo.enqueue_message(raw, "sender@local.test", ["user@local.test"], key)
    first = repo.claim_next_job()
    assert first["job_id"] == job_id

    recovered = repo.recover_stale_jobs(stale_seconds=0)
    assert recovered == 1
    second = repo.claim_next_job()
    assert second is not None
    assert second["job_id"] == job_id
    assert second["attempts"] == 2


def test_crash_window_is_explicitly_at_least_once(tmp_path):
    """SMTP cannot guarantee exactly-once across a crash after downstream 250.

    This test documents the remaining boundary: a delivery accepted downstream
    but not durably marked SENT before process death is retried after recovery.
    """
    repo = MessageRepository(str(tmp_path / "db.sqlite"), str(tmp_path / "data"))
    message_id = _seed_message(repo, ["user@local.test"])
    worker = DeliveryWorker(repo, SimpleNamespace(repository=repo), _settings())
    calls: list[str] = []

    original_mark = repo.mark_delivery_sent

    def accepted_then_crash(_delivery_id: str) -> None:
        # Downstream has accepted the message, then the process dies before the
        # local SENT state is committed. This is the unavoidable SMTP boundary.
        raise SystemExit("simulated crash after downstream acceptance")

    def send_one(_sender: str, recipient: str, _raw: bytes, _host: str, _port: int) -> None:
        calls.append(recipient)

    worker._send_one = send_one
    repo.mark_delivery_sent = accepted_then_crash  # type: ignore[method-assign]
    with pytest.raises(SystemExit):
        worker._deliver_due(message_id, {"sender": "sender@local.test", "attempts": 1, "job_id": "job"})

    repo.mark_delivery_sent = original_mark  # type: ignore[method-assign]
    assert calls == ["user@local.test"]
    assert repo.delivery_summary(message_id)["pending"] == 1

    # Recovery retries the durable PENDING record. The system is therefore
    # at-least-once, not exactly-once, across an arbitrary process crash.
    worker._deliver_due(message_id, {"sender": "sender@local.test", "attempts": 2, "job_id": "job"})
    assert calls == ["user@local.test", "user@local.test"]
    assert repo.delivery_summary(message_id)["sent"] == 1
