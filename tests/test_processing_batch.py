from __future__ import annotations

from app.application.policy import PolicyEngine
from app.application.processing_service import EmailProcessor
from app.domain.models import Classification, EmailDocument, GatewaySettings, RiskAssessment, ThreatCategory
from app.infrastructure.database.repository import MessageRepository
from app.infrastructure.risk.engine import RiskEngine


class FakeRiskEngine:
    def assess(self, email: EmailDocument) -> RiskAssessment:
        requires_ai = "THREAT" in email.subject
        return RiskAssessment(
            score=0.8 if requires_ai else 0.01,
            requires_ai=requires_ai,
            keywords=["test"] if requires_ai else [],
        )


class FakeClassifier:
    def __init__(self):
        self.batches = []

    def classify_many(self, emails: list[EmailDocument]) -> list[Classification]:
        self.batches.append([email.subject for email in emails])
        return [
            Classification(
                category=ThreatCategory.TERRORISM,
                is_threat=True,
                confidence=0.95,
                source="AI_BATCH",
            )
            for _email in emails
        ]

    def classify(self, email: EmailDocument) -> Classification:
        raise AssertionError("classify_many should be used for a multi-email batch")


def test_processor_batches_only_messages_that_require_ai(tmp_path):
    settings = GatewaySettings(data_dir=str(tmp_path / "data"), db_path=str(tmp_path / "db.sqlite"))
    repository = MessageRepository(settings.db_path, settings.data_dir)
    classifier = FakeClassifier()
    processor = EmailProcessor(classifier, PolicyEngine(settings), repository, FakeRiskEngine())
    prepared = [
        processor.prepare(b"Subject: benign 1\r\n\r\nhello", "key-1"),
        processor.prepare(b"Subject: THREAT 2\r\n\r\ntext", "key-2"),
        processor.prepare(b"Subject: benign 3\r\n\r\nhello", "key-3"),
        processor.prepare(b"Subject: THREAT 4\r\n\r\ntext", "key-4"),
    ]

    classifications = processor.classify_prepared_batch(prepared)

    assert len(classifications) == 4
    assert classifier.batches == [["THREAT 2", "THREAT 4"]]
    assert classifications[0].category == ThreatCategory.BENIGN
    assert classifications[1].category == ThreatCategory.TERRORISM
    assert classifications[2].category == ThreatCategory.BENIGN
    assert classifications[3].category == ThreatCategory.TERRORISM


def test_processor_rechecks_batch_benign_result_individually(tmp_path):
    settings = GatewaySettings(data_dir=str(tmp_path / "data"), db_path=str(tmp_path / "db.sqlite"))
    repository = MessageRepository(settings.db_path, settings.data_dir)

    class BatchBenignThenSingleThreat:
        def __init__(self):
            self.individual_calls = []

        def classify_many(self, emails: list[EmailDocument]) -> list[Classification]:
            return [
                Classification(
                    category=ThreatCategory.BENIGN,
                    is_threat=False,
                    confidence=1.0,
                    source="AI_BATCH",
                )
                for _email in emails
            ]

        def classify(self, email: EmailDocument) -> Classification:
            self.individual_calls.append(email.subject)
            return Classification(
                category=ThreatCategory.TERRORISM,
                is_threat=True,
                confidence=0.95,
                source="AI_UNIFIED",
            )

    classifier = BatchBenignThenSingleThreat()
    processor = EmailProcessor(classifier, PolicyEngine(settings), repository, FakeRiskEngine())
    prepared = [
        processor.prepare(b"Subject: THREAT 1\r\n\r\nexplicit threat", "key-1"),
        processor.prepare(b"Subject: THREAT 2\r\n\r\nexplicit threat", "key-2"),
    ]

    classifications = processor.classify_prepared_batch(prepared)

    assert [item.category for item in classifications] == [
        ThreatCategory.TERRORISM, ThreatCategory.TERRORISM
    ]
    assert all(item.is_threat for item in classifications)
    assert classifier.individual_calls == ["THREAT 1", "THREAT 2"]


def test_processor_rechecks_batch_other_threat_when_local_signals_exist(tmp_path):
    settings = GatewaySettings(data_dir=str(tmp_path / "data"), db_path=str(tmp_path / "db.sqlite"))
    repository = MessageRepository(settings.db_path, settings.data_dir)

    class BatchOtherThenSingleIllegal:
        def __init__(self):
            self.individual_calls = []

        def classify_many(self, emails: list[EmailDocument]) -> list[Classification]:
            return [
                Classification(
                    category=ThreatCategory.OTHER_THREAT,
                    is_threat=True,
                    confidence=0.86,
                    source="AI_BATCH",
                )
                for _email in emails
            ]

        def classify(self, email: EmailDocument) -> Classification:
            self.individual_calls.append(email.subject)
            return Classification(
                category=ThreatCategory.ILLEGAL,
                is_threat=True,
                confidence=0.91,
                source="AI_UNIFIED",
            )

    classifier = BatchOtherThenSingleIllegal()
    processor = EmailProcessor(classifier, PolicyEngine(settings), repository, FakeRiskEngine())
    prepared = [
        processor.prepare(b"Subject: THREAT 1\r\n\r\nexplicit threat", "key-1"),
        processor.prepare(b"Subject: THREAT 2\r\n\r\nexplicit threat", "key-2"),
    ]

    classifications = processor.classify_prepared_batch(prepared)

    assert [item.category for item in classifications] == [
        ThreatCategory.ILLEGAL, ThreatCategory.ILLEGAL
    ]
    assert all(item.is_threat for item in classifications)
    assert classifier.individual_calls == ["THREAT 1", "THREAT 2"]


def test_processor_does_not_leave_batch_benign_when_individual_verification_fails(tmp_path):
    settings = GatewaySettings(data_dir=str(tmp_path / "data"), db_path=str(tmp_path / "db.sqlite"))
    repository = MessageRepository(settings.db_path, settings.data_dir)

    class BatchBenignAndFallbackBenign:
        def classify_many(self, emails: list[EmailDocument]) -> list[Classification]:
            return [
                Classification(
                    category=ThreatCategory.BENIGN,
                    is_threat=False,
                    confidence=1.0,
                    source="AI_BATCH",
                )
                for _email in emails
            ]

        def classify(self, email: EmailDocument) -> Classification:
            return Classification(
                category=ThreatCategory.BENIGN,
                is_threat=False,
                confidence=0.20,
                source="FALLBACK",
            )

    processor = EmailProcessor(
        BatchBenignAndFallbackBenign(), PolicyEngine(settings), repository, FakeRiskEngine()
    )
    prepared = [
        processor.prepare(b"Subject: THREAT 1\r\n\r\nexplicit threat", "key-1"),
        processor.prepare(b"Subject: THREAT 2\r\n\r\nexplicit threat", "key-2"),
    ]

    classifications = processor.classify_prepared_batch(prepared)

    assert all(item.is_threat for item in classifications)
    assert all(item.category == ThreatCategory.OTHER_THREAT for item in classifications)
    assert all(item.source == "FALLBACK" for item in classifications)


def test_processor_sends_disputed_results_to_batched_reviewer(tmp_path):
    settings = GatewaySettings(data_dir=str(tmp_path / "data"), db_path=str(tmp_path / "db.sqlite"))
    repository = MessageRepository(settings.db_path, settings.data_dir)

    class PrimaryAndReviewClassifier:
        def __init__(self):
            self.review_calls = []

        def classify_many(self, emails: list[EmailDocument]) -> list[Classification]:
            return [
                Classification(
                    category=ThreatCategory.BENIGN,
                    is_threat=False,
                    confidence=1.0,
                    source="AI_BATCH",
                )
                for _email in emails
            ]

        def review_many(self, emails, initial_results, risk_contexts):
            self.review_calls.append((list(emails), list(initial_results), list(risk_contexts)))
            return [
                Classification(
                    category=ThreatCategory.ILLEGAL,
                    is_threat=True,
                    confidence=0.91,
                    source="AI_BATCH_REVIEW",
                )
                for _email in emails
            ]

    classifier = PrimaryAndReviewClassifier()
    processor = EmailProcessor(classifier, PolicyEngine(settings), repository, FakeRiskEngine())
    prepared = [
        processor.prepare(b"Subject: THREAT one\r\n\r\nfirst threat text", "key-1"),
        processor.prepare(b"Subject: THREAT two\r\n\r\nsecond threat text", "key-2"),
    ]

    results = processor.classify_prepared_batch(prepared)

    assert len(classifier.review_calls) == 1
    assert len(classifier.review_calls[0][0]) == 2
    assert [result.category for result in results] == [ThreatCategory.ILLEGAL, ThreatCategory.ILLEGAL]
    assert all(result.source == "AI_BATCH_REVIEW" for result in results)


def test_zero_local_score_batch_benign_results_are_still_reviewed(tmp_path):
    settings = GatewaySettings(
        data_dir=str(tmp_path / "data"),
        db_path=str(tmp_path / "db.sqlite"),
        risk_training_path="config/risk_training.json",
    )
    repository = MessageRepository(settings.db_path, settings.data_dir)

    class AlwaysBenignClassifier:
        def __init__(self):
            self.reviewed_subjects = []

        def classify_many(self, emails):
            return [
                Classification(
                    category=ThreatCategory.BENIGN,
                    is_threat=False,
                    confidence=0.99,
                    source="AI_BATCH",
                )
                for _email in emails
            ]

        def review_many(self, emails, initial_results, risk_contexts):
            self.reviewed_subjects.extend(email.subject for email in emails)
            return [
                Classification(
                    category=ThreatCategory.OTHER_THREAT,
                    is_threat=True,
                    confidence=0.90,
                    source="AI_BATCH_REVIEW",
                )
                for _email in emails
            ]

    classifier = AlwaysBenignClassifier()
    processor = EmailProcessor(classifier, PolicyEngine(settings), repository, RiskEngine(settings))
    messages = [
        ("Призыв", "Призываем к насилию: все объекты будут уничтожены, если требования не будут выполнены."),
        ("Скоро", "Скоро всё сгорит. Готовьтесь к большой огненной атаке на наши цели."),
        ("Требование", "Похищу твоего сына, если моё требование не будет выполнено сегодня."),
    ]
    prepared = [
        processor.prepare(f"Subject: {subject}\r\n\r\n{body}".encode("utf-8"), f"key-{index}")
        for index, (subject, body) in enumerate(messages)
    ]

    assert all(item.risk.requires_ai for item in prepared)
    assert all(item.risk.score == 0.0 for item in prepared)
    results = processor.classify_prepared_batch(prepared)

    assert classifier.reviewed_subjects == [subject for subject, _body in messages]
    assert all(result.is_threat for result in results)


def test_api_fallback_does_not_silently_accept_ai_required_benign(tmp_path):
    settings = GatewaySettings(data_dir=str(tmp_path / "data"), db_path=str(tmp_path / "db.sqlite"))
    repository = MessageRepository(settings.db_path, settings.data_dir)

    class FallbackBenignClassifier:
        def classify_many(self, emails):
            return [
                Classification(
                    category=ThreatCategory.BENIGN,
                    is_threat=False,
                    confidence=0.99,
                    source="FALLBACK",
                )
                for _email in emails
            ]

        def classify(self, email):
            raise AssertionError("API fallback should not start another network request")

    processor = EmailProcessor(
        FallbackBenignClassifier(),
        PolicyEngine(settings),
        repository,
        FakeRiskEngine(),
    )
    prepared = [processor.prepare(b"Subject: THREAT ambiguous\r\n\r\nunresolved message", "key")]

    result = processor.classify_prepared_batch(prepared)[0]

    assert result.is_threat is True
    assert result.category == ThreatCategory.OTHER_THREAT
    assert result.source == "FALLBACK"
