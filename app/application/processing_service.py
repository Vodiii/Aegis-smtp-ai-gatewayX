from __future__ import annotations

import logging
import time
import uuid

from app.application.policy import PolicyEngine
from app.domain.models import EmailDocument, ProcessingResult
from app.infrastructure.database.repository import MessageRepository
from app.infrastructure.deepseek.client import DeepSeekClient

LOGGER = logging.getLogger(__name__)


class EmailProcessor:
    def __init__(self, classifier: DeepSeekClient, policy: PolicyEngine, repository: MessageRepository) -> None:
        self.classifier = classifier
        self.policy = policy
        self.repository = repository

    def process(self, raw_message: bytes) -> tuple[str, EmailDocument, ProcessingResult]:
        start = time.perf_counter()
        from app.infrastructure.parser.email_parser import EmailParser
        email = EmailParser(self.policy.settings.max_ai_text_chars).parse(raw_message)
        classification = self.classifier.classify(email)
        decision = self.policy.decide(classification)
        processing_ms = int((time.perf_counter() - start) * 1000)
        result = ProcessingResult(
            classification=classification,
            decision=decision,
            processing_time_ms=processing_ms,
        )
        record_id = str(uuid.uuid4())
        self.repository.save(record_id, raw_message, email, result)
        return record_id, email, result
