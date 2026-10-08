from pathlib import Path

from app.domain.models import (
    Classification,
    GatewaySettings,
    PolicyDecision,
    ProcessingResult,
    ThreatCategory,
    Action,
    EmailDocument,
)
from app.infrastructure.database.repository import MessageRepository


def test_repository_saves_threat_confidence_and_round_trips(tmp_path: Path):
    repo = MessageRepository(str(tmp_path / "gateway.db"), str(tmp_path / "data"))
    result = ProcessingResult(
        classification=Classification(
            category=ThreatCategory.TERRORISM,
            is_threat=True,
            confidence=0.72,
            threat_confidence=0.93,
            reason="credible threat",
            evidence=["угроза"],
        ),
        decision=PolicyDecision(
            action=Action.DELIVER_AND_ALERT,
            category=ThreatCategory.TERRORISM,
            confidence=0.72,
            destination="alerts-terrorism@local.test",
            review=False,
        ),
        processing_time_ms=123,
    )
    email = EmailDocument(
        message_id="<test@example.com>",
        sender="sender@example.com",
        recipients=["user@local.test"],
        subject="Threat",
        text="body",
    )

    repo.save("record-1", b"Subject: Threat\n\nbody", email, result)
    record = repo.get("record-1")

    assert record is not None
    assert record["threat_confidence"] == 0.93
    assert record["category"] == "TERRORISM"
    assert record["action"] == "DELIVER_AND_ALERT"
    assert record["classification_source"] == "AI_TWO_STAGE"


def test_repository_persists_processing_timestamps_and_stats(tmp_path: Path):
    from datetime import datetime, timezone
    from app.domain.models import Action, Classification, PolicyDecision, ProcessingResult, ThreatCategory

    repo = MessageRepository(str(tmp_path / "gateway.db"), str(tmp_path / "data"))
    started = datetime.now(timezone.utc)
    finished = started.replace(microsecond=started.microsecond + 1000)
    result = ProcessingResult(
        classification=Classification(category=ThreatCategory.BENIGN, is_threat=False, confidence=0.99),
        decision=PolicyDecision(action=Action.DELIVER, category=ThreatCategory.BENIGN, confidence=0.99),
        processing_time_ms=42,
        processing_started_at=started,
        processing_finished_at=finished,
    )
    repo.save("timing-1", b"Subject: x\n\nbody", EmailDocument(sender="sender@local.test"), result)
    row = repo.get("timing-1")
    assert row["processing_time_ms"] == 42
    assert row["processing_started_at"] == started.isoformat()
    assert row["processing_finished_at"] == finished.isoformat()
    stats = repo.stats()
    assert stats["timing"]["total_processing_ms"] == 42
    assert stats["timing"]["avg_processing_ms"] == 42.0
    assert stats["timing"]["min_processing_ms"] == 42
    assert stats["timing"]["max_processing_ms"] == 42
