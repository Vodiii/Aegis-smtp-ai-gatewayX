from __future__ import annotations

import json

import httpx

from app.domain.models import Classification, EmailDocument, ThreatCategory
from app.infrastructure.deepseek.client import DeepSeekClient


def _response(body: dict) -> httpx.Response:
    return httpx.Response(
        200,
        json={"choices": [{"message": {"content": json.dumps(body, ensure_ascii=False)}}]},
        request=httpx.Request("POST", "https://api.deepseek.com/chat/completions"),
    )


def test_batch_classification_uses_one_http_request_and_keeps_order(monkeypatch):
    calls = []

    def fake_post(*args, **kwargs):
        calls.append(kwargs["json"])
        return _response({
            "results": [
                {"id": 1, "is_threat": True, "category": "TECHNOGENIC", "confidence": 0.91,
                 "threat_confidence": 0.94, "reason": "Техногенная угроза", "evidence": ["утечка"]},
                {"id": 0, "is_threat": False, "category": "BENIGN", "confidence": 0.98,
                 "threat_confidence": 0.02, "reason": "Обычное письмо", "evidence": []},
            ]
        })

    monkeypatch.setattr(httpx.Client, "post", fake_post)
    client = DeepSeekClient("primary", "deepseek-flash", batch_size=10)
    try:
        results = client.classify_many([
            EmailDocument(subject="Сводка", text="Обычная рабочая сводка"),
            EmailDocument(subject="Авария", text="Возможна утечка хлора на объекте завтра"),
        ])
        assert len(calls) == 1
        assert len(results) == 2
        assert results[0].category == ThreatCategory.BENIGN
        assert results[1].category == ThreatCategory.TECHNOGENIC
        assert results[1].is_threat is True
        assert all(result.source == "AI_BATCH" for result in results)
        assert client.request_count == 1
    finally:
        client.close()


def test_batch_classification_chunks_at_configured_size(monkeypatch):
    calls = []

    def fake_post(*args, **kwargs):
        calls.append(kwargs["json"])
        emails = json.loads(kwargs["json"]["messages"][1]["content"])["emails"]
        return _response({"results": [
            {"id": item["id"], "is_threat": False, "category": "BENIGN", "confidence": 0.99,
             "threat_confidence": 0.01, "reason": "Обычное письмо", "evidence": []}
            for item in emails
        ]})

    monkeypatch.setattr(httpx.Client, "post", fake_post)
    client = DeepSeekClient("primary", "deepseek-flash", batch_size=3)
    try:
        emails = [EmailDocument(subject=f"Тест {i}", text="Проверка") for i in range(8)]
        results = client.classify_many(emails)
        assert len(results) == 8
        assert len(calls) == 3
        assert [len(json.loads(call["messages"][1]["content"])["emails"]) for call in calls] == [3, 3, 2]
        assert all(result.category == ThreatCategory.BENIGN for result in results)
    finally:
        client.close()


def test_missing_batch_item_uses_visible_fallback_without_extra_single_requests(monkeypatch):
    calls = []

    def fake_post(*args, **kwargs):
        calls.append(kwargs["json"])
        user_payload = kwargs["json"]["messages"][1]["content"]
        if '"emails"' in user_payload:
            return _response({"results": [
                {"id": 0, "is_threat": False, "category": "BENIGN", "confidence": 0.99,
                 "threat_confidence": 0.01, "reason": "Обычное письмо", "evidence": []},
            ]})
        return _response({
            "is_threat": True, "category": "ILLEGAL", "confidence": 0.90,
            "threat_confidence": 0.92, "reason": "Прямая угроза", "evidence": ["убью"]
        })

    monkeypatch.setattr(httpx.Client, "post", fake_post)
    client = DeepSeekClient("primary", "deepseek-flash", batch_size=10)
    try:
        results = client.classify_many([
            EmailDocument(subject="Обычное", text="Сводка за неделю"),
            EmailDocument(subject="Угроза", text="Найду тебя и убью"),
        ])
        assert len(results) == 2
        assert results[0].category == ThreatCategory.BENIGN
        assert results[1].category == ThreatCategory.OTHER_THREAT
        assert results[1].source == "AI_BATCH_INVALID"
        assert len(calls) == 1
    finally:
        client.close()


def test_batch_review_reuses_single_api_key_and_batches_candidates(monkeypatch):
    calls = []

    def fake_post(*args, **kwargs):
        payload = kwargs["json"]
        calls.append((kwargs["headers"]["Authorization"], payload))
        user_data = json.loads(payload["messages"][1]["content"])
        emails = user_data["emails"]
        if "SECOND-PASS REVIEW TASK" not in payload["messages"][0]["content"]:
            return _response({"results": [
                {"id": item["id"], "is_threat": False, "category": "BENIGN", "confidence": 1.0,
                 "threat_confidence": 0.0, "reason": "Первичный проход", "evidence": []}
                for item in emails
            ]})
        return _response({"results": [
            {"id": item["id"], "is_threat": True, "category": "ILLEGAL", "confidence": 0.91,
             "threat_confidence": 0.93, "reason": "Вторичная проверка обнаружила угрозу", "evidence": ["убью"]}
            for item in emails
        ]})

    monkeypatch.setattr(httpx.Client, "post", fake_post)
    client = DeepSeekClient(
        "primary", "deepseek-flash", batch_size=10,
        review_batch_size=2, review_batch_wait_seconds=0.02,
    )
    try:
        emails = [
            EmailDocument(subject="Первое", text="Я тебя найду и лишу жизни."),
            EmailDocument(subject="Второе", text="Если не выполнишь требование, убью."),
        ]
        primary_results = client.classify_many(emails)
        assert all(result.category == ThreatCategory.BENIGN for result in primary_results)

        reviewed = client.review_many(
            emails,
            primary_results,
            [
                {"score": 0.1, "requires_ai": True, "keywords": [], "phrases": []},
                {"score": 0.2, "requires_ai": True, "keywords": ["угроза"], "phrases": []},
            ],
        )

        assert len(calls) == 2
        assert [authorization for authorization, _ in calls] == ["Bearer primary", "Bearer primary"]
        review_payload = calls[1][1]
        assert "SECOND-PASS REVIEW TASK" in review_payload["messages"][0]["content"]
        assert len(json.loads(review_payload["messages"][1]["content"])["emails"]) == 2
        assert all(result.category == ThreatCategory.ILLEGAL for result in reviewed)
        assert all(result.source == "AI_BATCH_REVIEW" for result in reviewed)
    finally:
        client.close()


def test_review_queue_combines_concurrent_candidates_on_single_key(monkeypatch):
    import threading

    calls = []

    def fake_post(*args, **kwargs):
        calls.append((kwargs["headers"]["Authorization"], kwargs["json"]))
        user_data = json.loads(kwargs["json"]["messages"][1]["content"])
        emails = user_data["emails"]
        return _response({"results": [
            {"id": item["id"], "is_threat": True, "category": "OTHER_THREAT", "confidence": 0.88,
             "threat_confidence": 0.90, "reason": "Проверка повторным этапом", "evidence": ["угроза"]}
            for item in emails
        ]})

    monkeypatch.setattr(httpx.Client, "post", fake_post)
    client = DeepSeekClient(
        "primary", "deepseek-flash", batch_size=10,
        review_batch_size=2, review_batch_wait_seconds=0.25,
    )
    initial = Classification(
        category=ThreatCategory.BENIGN, is_threat=False, confidence=0.99, source="AI_BATCH"
    )
    emails = [
        EmailDocument(subject="Review A", text="Первое спорное сообщение"),
        EmailDocument(subject="Review B", text="Второе спорное сообщение"),
    ]
    results = [None, None]

    def submit(index):
        results[index] = client.review_many(
            [emails[index]], [initial], [{"score": 0.2, "requires_ai": True, "keywords": [], "phrases": []}]
        )[0]

    try:
        first = threading.Thread(target=submit, args=(0,))
        second = threading.Thread(target=submit, args=(1,))
        first.start()
        second.start()
        first.join(timeout=3)
        second.join(timeout=3)
        assert not first.is_alive() and not second.is_alive()
        assert len(calls) == 1
        assert calls[0][0] == "Bearer primary"
        assert len(json.loads(calls[0][1]["messages"][1]["content"])["emails"]) == 2
        assert all(result is not None and result.is_threat for result in results)
    finally:
        client.close()


def test_review_failure_does_not_leave_disputed_benign_silent(monkeypatch):
    def fake_post(*args, **kwargs):
        return httpx.Response(
            503,
            json={"error": "temporary failure"},
            request=httpx.Request("POST", "https://api.deepseek.com/chat/completions"),
        )

    monkeypatch.setattr(httpx.Client, "post", fake_post)
    client = DeepSeekClient(
        "primary", "deepseek-flash",
        max_retries=0, review_batch_wait_seconds=0,
    )
    initial = Classification(
        category=ThreatCategory.BENIGN,
        is_threat=False,
        confidence=0.99,
        source="AI_BATCH",
    )
    try:
        result = client.review_many(
            [EmailDocument(subject="Спорное письмо", text="Требуется перепроверка")],
            [initial],
            [{"score": 0.2, "requires_ai": True, "keywords": ["сигнал"], "phrases": []}],
        )[0]
        assert result.category == ThreatCategory.OTHER_THREAT
        assert result.is_threat is True
        assert result.source == "FALLBACK"
    finally:
        client.close()
