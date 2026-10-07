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

def test_fallback_when_all_keys_fail(monkeypatch):
    import httpx as httpx_module

    def fake_post(*args, **kwargs):
        raise httpx_module.ConnectError("network down")

    monkeypatch.setattr(httpx_module, "post", fake_post)
    client = DeepSeekClient("key1", "key2", "deepseek-flash")
    result = client.classify(EmailDocument(subject="test", text="завтра взорву офис"))

    assert result.source == "FALLBACK"
    assert result.is_threat is True
    assert result.category == ThreatCategory.TERRORISM


def test_fallback_ignores_non_threat(monkeypatch):
    import httpx as httpx_module

    def fake_post(*args, **kwargs):
        raise httpx_module.ConnectError("network down")

    monkeypatch.setattr(httpx_module, "post", fake_post)
    client = DeepSeekClient("key1", None, "deepseek-flash")
    result = client.classify(EmailDocument(subject="test", text="обычное письмо про встречу"))

    assert result.source == "FALLBACK"
    assert result.category == ThreatCategory.BENIGN