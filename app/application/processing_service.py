from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from app.application.policy import PolicyEngine
from app.domain.models import Classification, EmailDocument, ProcessingResult, RiskAssessment, ThreatCategory
from app.infrastructure.database.repository import MessageRepository
from app.infrastructure.deepseek.client import DeepSeekClient
from app.infrastructure.deepseek.signals import detect_high_signal_conflicts
from app.infrastructure.parser.email_parser import EmailParser
from app.infrastructure.risk.engine import RiskEngine

LOGGER = logging.getLogger("app.processing")


@dataclass
class PreparedMessage:
    """Подготовленное письмо, ожидающее локальной или пакетной классификации."""

    raw_message: bytes
    delivery_key: str | None
    email: EmailDocument
    risk: RiskAssessment
    started_at: datetime
    timer_started: float


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

    def prepare(self, raw_message: bytes, delivery_key: str | None = None) -> PreparedMessage:
        """Разобрать письмо и вычислить локальный риск без вызова внешнего ИИ."""
        started_at = datetime.now(timezone.utc)
        timer_started = time.perf_counter()
        email = self.parser.parse(raw_message)
        risk = self.risk_engine.assess(email)
        return PreparedMessage(
            raw_message=raw_message,
            delivery_key=delivery_key,
            email=email,
            risk=risk,
            started_at=started_at,
            timer_started=timer_started,
        )

    def classify_prepared_batch(self, prepared: list[PreparedMessage]) -> list[Classification]:
        """Классифицировать локальные результаты вместе, пакетируя только AI-письма."""
        if not prepared:
            return []

        output: list[Classification | None] = [None] * len(prepared)
        ai_indexes: list[int] = []
        ai_emails: list[EmailDocument] = []

        for index, item in enumerate(prepared):
            if item.risk.requires_ai:
                ai_indexes.append(index)
                ai_emails.append(item.email)
            else:
                output[index] = Classification(
                    category=ThreatCategory.BENIGN,
                    is_threat=False,
                    confidence=max(0.0, min(1.0, 1.0 - item.risk.score)),
                    threat_confidence=max(0.0, min(1.0, item.risk.score)),
                    reason="Локальный Risk Engine определил низкий риск; вызов DeepSeek не потребовался",
                    evidence=item.risk.keywords + item.risk.phrases,
                    source="FAST_RISK_GATE",
                )

        if ai_emails:
            classify_many = getattr(self.classifier, "classify_many", None)
            if callable(classify_many):
                ai_results = classify_many(ai_emails)
            else:
                ai_results = [self.classifier.classify(email) for email in ai_emails]
            if len(ai_results) != len(ai_indexes):
                raise RuntimeError(
                    f"Classifier returned {len(ai_results)} results for {len(ai_indexes)} emails"
                )

            review_indexes: list[int] = []
            review_emails: list[EmailDocument] = []
            review_initial: list[Classification] = []
            review_contexts: list[dict[str, object]] = []

            for index, classification in zip(ai_indexes, ai_results):
                item = prepared[index]
                output[index] = classification
                if classification.source == "FALLBACK" and not classification.is_threat and item.risk.requires_ai:
                    classification = self._review_unavailable_fallback(
                        classification,
                        {
                            "score": item.risk.score,
                            "keywords": item.risk.keywords,
                            "phrases": item.risk.phrases,
                        },
                    )
                    output[index] = classification
                source_is_primary_ai = classification.source in {
                    "AI_BATCH", "AI_UNIFIED", "AI_TWO_STAGE", "AI_THREAT_GATE", "AI_BATCH_INVALID"
                }
                signals = detect_high_signal_conflicts(item.email.subject, item.email.text)
                has_local_signals = bool(item.risk.keywords or item.risk.phrases or item.risk.obfuscation_detected)
                category_needs_review = (
                    classification.category == ThreatCategory.OTHER_THREAT
                    and (
                        item.risk.score >= 0.15
                        or has_local_signals
                        or classification.confidence < 0.90
                    )
                )
                high_signal_conflict = bool(signals) and (
                    not classification.is_threat
                    or any(signal.category != classification.category.value for signal in signals)
                )
                should_review = source_is_primary_ai and (
                    not classification.is_threat
                    or category_needs_review
                    or classification.confidence < 0.85
                    or high_signal_conflict
                    or classification.source == "AI_BATCH_INVALID"
                )
                if should_review:
                    review_indexes.append(index)
                    review_emails.append(item.email)
                    review_initial.append(classification)
                    review_contexts.append({
                        "score": item.risk.score,
                        "requires_ai": item.risk.requires_ai,
                        "keywords": item.risk.keywords,
                        "phrases": item.risk.phrases,
                        "obfuscation_detected": item.risk.obfuscation_detected,
                        "reason": item.risk.reason,
                    })

            if review_emails:
                LOGGER.info(
                    "Результаты для повторной проверки: %d из %d AI-писем",
                    len(review_emails),
                    len(ai_emails),
                )
                review_many = getattr(self.classifier, "review_many", None)
                if callable(review_many):
                    try:
                        reviewed_results = review_many(review_emails, review_initial, review_contexts)
                    except Exception:
                        LOGGER.exception("Не удалось выполнить пакетную повторную проверку")
                        reviewed_results = [
                            self._review_unavailable_fallback(initial, context)
                            for initial, context in zip(review_initial, review_contexts)
                        ]
                else:
                    # Совместимость с тестовыми классификаторами и старыми реализациями без пакетного этапа.
                    reviewed_results = []
                    for email, initial, context in zip(review_emails, review_initial, review_contexts):
                        try:
                            reviewed = self.classifier.classify(email)
                        except Exception:
                            LOGGER.exception("Не удалось повторно проверить письмо: %s", email.subject)
                            reviewed = self._review_unavailable_fallback(initial, context)
                        if reviewed.source == "FALLBACK" and not reviewed.is_threat and not initial.is_threat:
                            reviewed = self._review_unavailable_fallback(initial, context)
                        reviewed_results.append(reviewed)

                if len(reviewed_results) != len(review_indexes):
                    raise RuntimeError(
                        f"Проверяющий этап вернул {len(reviewed_results)} результатов для {len(review_indexes)} писем"
                    )
                for index, initial, reviewed in zip(review_indexes, review_initial, reviewed_results):
                    if (
                        reviewed.category != initial.category
                        or reviewed.is_threat != initial.is_threat
                    ):
                        LOGGER.warning(
                            "Повторная проверка изменила результат: %s/%s -> %s/%s",
                            initial.category.value,
                            initial.is_threat,
                            reviewed.category.value,
                            reviewed.is_threat,
                        )
                    output[index] = reviewed

        if any(item is None for item in output):
            raise RuntimeError("One or more messages did not receive a classification")
        return [item for item in output if item is not None]

    @staticmethod
    def _review_unavailable_fallback(
        initial: Classification,
        risk_context: dict[str, object],
    ) -> Classification:
        """Отправить спорный результат на ручную проверку, если резервный ИИ недоступен."""
        if initial.is_threat:
            return initial.model_copy(
                update={
                    "source": "FALLBACK",
                    "reason": "Повторная проверка ИИ недоступна; сохранено решение первичного этапа. " + initial.reason,
                }
            )
        score = float(risk_context.get("score", 0.0) or 0.0)
        keywords = list(risk_context.get("keywords", []))
        phrases = list(risk_context.get("phrases", []))
        return Classification(
            category=ThreatCategory.OTHER_THREAT,
            is_threat=True,
            confidence=max(0.50, min(0.75, score)),
            threat_confidence=max(0.50, min(0.75, score)),
            reason="Повторная проверка ИИ недоступна; требуется ручная оценка службой безопасности.",
            evidence=list(dict.fromkeys(keywords + phrases)),
            source="FALLBACK",
        )

    def finish_prepared(
        self,
        prepared: PreparedMessage,
        classification: Classification,
    ) -> tuple[str, EmailDocument, ProcessingResult]:
        """Сохранить классификацию, решение policy и результат обработки письма."""
        decision = self.policy.decide(classification)
        finished_at = datetime.now(timezone.utc)
        processing_ms = int((time.perf_counter() - prepared.timer_started) * 1000)
        result = ProcessingResult(
            classification=classification,
            decision=decision,
            processing_time_ms=processing_ms,
            processing_started_at=prepared.started_at,
            processing_finished_at=finished_at,
            risk_assessment=prepared.risk,
        )
        record_id = str(uuid.uuid4())
        self.repository.save(
            record_id,
            prepared.raw_message,
            prepared.email,
            result,
            delivery_key=prepared.delivery_key,
        )
        return record_id, prepared.email, result

    def process(self, raw_message: bytes, delivery_key: str | None = None) -> tuple[str, EmailDocument, ProcessingResult]:
        """Обработать одно письмо, сохраняя прежний интерфейс для совместимости."""
        prepared = self.prepare(raw_message, delivery_key=delivery_key)
        classification = self.classify_prepared_batch([prepared])[0]
        return self.finish_prepared(prepared, classification)

