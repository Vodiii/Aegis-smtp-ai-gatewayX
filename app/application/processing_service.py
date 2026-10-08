from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

from app.application.policy import PolicyEngine
from app.domain.models import Classification, EmailDocument, ProcessingResult, ThreatCategory
from app.infrastructure.database.repository import MessageRepository
from app.infrastructure.deepseek.client import DeepSeekClient
from app.infrastructure.parser.email_parser import EmailParser
from app.infrastructure.risk.engine import RiskEngine


class EmailProcessor:
    def __init__(
        self,
        classifier: DeepSeekClient,
        policy: PolicyEngine,
        repository: MessageRepository,
        risk_engine: RiskEngine,
    ) -> None:
        self.classifier = classifier
        self.policy = policy
        self.repository = repository
        self.risk_engine = risk_engine
        self.parser = EmailParser(
            max_text_chars=self.policy.settings.max_ai_text_chars,
            max_attachments=self.policy.settings.max_attachments,
        )

    def process(self, raw_message: bytes, delivery_key: str | None = None) -> tuple[str, EmailDocument, ProcessingResult]:
        started_at = datetime.now(timezone.utc)
        start = time.perf_counter()
        email = self.parser.parse(raw_message)
        risk = self.risk_engine.assess(email)

        if risk.requires_ai:
            classification = self.classifier.classify(email)
        else:
            classification = Classification(
                category=ThreatCategory.BENIGN,
                is_threat=False,
                confidence=max(0.0, min(1.0, 1.0 - risk.score)),
                threat_confidence=max(0.0, min(1.0, risk.score)),
                reason="Fast Risk Engine classified the message as low risk; DeepSeek was not called",
                evidence=risk.keywords + risk.phrases,
                source="FAST_RISK_GATE",
            )

        decision = self.policy.decide(classification)
        finished_at = datetime.now(timezone.utc)
        processing_ms = int((time.perf_counter() - start) * 1000)
        result = ProcessingResult(
            classification=classification,
            decision=decision,
            processing_time_ms=processing_ms,
            processing_started_at=started_at,
            processing_finished_at=finished_at,
            risk_assessment=risk,
        )
        record_id = str(uuid.uuid4())
        self.repository.save(record_id, raw_message, email, result, delivery_key=delivery_key)
        return record_id, email, result

