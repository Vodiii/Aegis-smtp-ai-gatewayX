import json

import httpx

from app.domain.models import EmailDocument, ThreatCategory
from app.infrastructure.deepseek.client import DeepSeekClient


def test_two_stage_classification(monkeypatch):
    responses = iter([
        {
            "is_threat": True,
            "confidence": 0.91,
            "reason": "credible threat",
            "evidence": ["прямая угроза"],
        },
        {
            "category": "TECHNOGENIC",
            "confidence": 0.93,
            "reason": "industrial accident threat",
            "evidence": ["авария на заводе"],
        },
    ])

    def fake_post(*args, **kwargs):
        body = next(responses)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps(body, ensure_ascii=False)}}]},
            request=httpx.Request("POST", "https://api.deepseek.com/chat/completions"),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    client = DeepSeekClient("primary", None, "deepseek-flash")
    result = client.classify(EmailDocument(subject="test", text="text"))

    assert result.category == ThreatCategory.TECHNOGENIC
    assert result.is_threat is True
    assert result.threat_confidence == 0.91
    assert result.confidence == 0.93
    assert result.source == "AI_TWO_STAGE"


def test_non_threat_stops_before_category(monkeypatch):
    calls = []

    def fake_post(*args, **kwargs):
        calls.append(1)
        body = {
            "is_threat": False,
            "confidence": 0.98,
            "reason": "ordinary message",
            "evidence": [],
        }
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps(body)}}]},
            request=httpx.Request("POST", "https://api.deepseek.com/chat/completions"),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    client = DeepSeekClient("primary", None, "deepseek-flash")
    result = client.classify(EmailDocument(subject="test", text="обычное письмо"))

    assert result.category == ThreatCategory.BENIGN
    assert result.is_threat is False
    assert len(calls) == 1


def test_unified_classification_uses_one_call(monkeypatch):
    calls = []

    def fake_post(*args, **kwargs):
        calls.append(1)
        body = {
            "is_threat": True,
            "category": "ILLEGAL",
            "confidence": 0.94,
            "threat_confidence": 0.97,
            "reason": "direct unlawful threat",
            "evidence": ["найду тебя и убью"],
        }
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps(body, ensure_ascii=False)}}]},
            request=httpx.Request("POST", "https://api.deepseek.com/chat/completions"),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    client = DeepSeekClient("primary", None, "deepseek-flash")
    result = client.classify(EmailDocument(subject="test", text="Найду тебя и убью."))

    assert result.category == ThreatCategory.ILLEGAL
    assert result.is_threat is True
    assert result.source == "AI_UNIFIED"
    assert result.threat_confidence == 0.97
    assert len(calls) == 1


def test_category_policy_correction_does_not_add_ai_call(monkeypatch):
    cases = [
        ("Залью твои переписки и фото в сеть, если не заплатишь.", "ILLEGAL", "OTHER_THREAT"),
        ("Запущу вирус в систему водоснабжения города.", "TECHNOGENIC", "OTHER_THREAT"),
    ]

    for text, ai_category, expected_category in cases:
        calls = []

        def fake_post(*args, _category=ai_category, **kwargs):
            calls.append(1)
            body = {
                "is_threat": True,
                "category": _category,
                "confidence": 0.95,
                "threat_confidence": 0.96,
                "reason": "mock category",
                "evidence": [],
            }
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": json.dumps(body, ensure_ascii=False)}}]},
                request=httpx.Request("POST", "https://api.deepseek.com/chat/completions"),
            )

        monkeypatch.setattr(httpx, "post", fake_post)
        client = DeepSeekClient("primary", None, "deepseek-flash")
        result = client.classify(EmailDocument(text=text))

        assert result.category.value == expected_category
        assert len(calls) == 1
