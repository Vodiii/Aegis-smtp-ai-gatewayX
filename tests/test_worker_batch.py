from __future__ import annotations

from app.application.policy import PolicyEngine
from app.application.processing_service import EmailProcessor
from app.domain.models import Classification, EmailDocument, GatewaySettings, RiskAssessment, ThreatCategory
from app.infrastructure.database.repository import MessageRepository
from app.infrastructure.queue.worker import DeliveryWorker


class FakeRiskEngine:
    def assess(self, email: EmailDocument) -> RiskAssessment:
        is_risky = "THREAT" in email.subject
        return RiskAssessment(
            score=0.9 if is_risky else 0.01,
            requires_ai=is_risky,
            keywords=["synthetic test"] if is_risky else [],
        )


class FakeBatchClassifier:
    def __init__(self):
        self.batches: list[list[str]] = []

    def classify_many(self, emails: list[EmailDocument]) -> list[Classification]:
        self.batches.append([email.subject for email in emails])
        return [
            Classification(
                category=ThreatCategory.TERRORISM,
                is_threat=True,
                confidence=0.95,
                source="AI_UNIFIED",
            )
            for _email in emails
        ]

    def classify(self, email: EmailDocument) -> Classification:
        raise AssertionError("В этом тесте ожидалась пакетная классификация")


def test_worker_groups_queue_jobs_and_batches_only_ai_candidates(tmp_path):
    settings = GatewaySettings(
        data_dir=str(tmp_path / "data"),
        db_path=str(tmp_path / "db.sqlite"),
        original_smtp_host="original",
        original_smtp_port=1025,
        alert_smtp_host="alerts",
        alert_smtp_port=1025,
        queue_batch_max_messages=10,
        queue_batch_wait_seconds=0,
    )
    repository = MessageRepository(settings.db_path, settings.data_dir)
    repository.configure_delivery_endpoints(settings)
    classifier = FakeBatchClassifier()
    processor = EmailProcessor(classifier, PolicyEngine(settings), repository, FakeRiskEngine())

    for index, subject in enumerate(("BENIGN one", "THREAT two", "BENIGN three", "THREAT four")):
        raw = (
            f"From: sender@local.test\r\nTo: user@local.test\r\n"
            f"Subject: {subject}\r\n\r\nTest body {index}\r\n"
        ).encode("utf-8")
        delivery_key = repository.make_delivery_key(raw, "sender@local.test", ["user@local.test"])
        repository.enqueue_message(raw, "sender@local.test", ["user@local.test"], delivery_key)

    worker = DeliveryWorker(repository, processor, settings)
    sent: list[tuple[str, str]] = []
    worker._send_one = lambda sender, recipient, raw, host, port: sent.append((recipient, host))

    first = repository.claim_next_job()
    assert first is not None
    batch = worker._collect_batch(first)
    assert len(batch) == 4
    worker._process_jobs(batch)

    assert classifier.batches == [["THREAT two", "THREAT four"]]
    assert len(sent) == 6
    assert len(repository.list_messages(limit=20)) == 4
