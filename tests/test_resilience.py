import json

import httpx

from app.application.policy import PolicyEngine
from app.domain.models import Classification, EmailDocument, GatewaySettings, ThreatCategory, Action
from app.infrastructure.deepseek.client import DeepSeekClient


def _response(body: dict, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status,
        json={"choices": [{"message": {"content": json.dumps(body, ensure_ascii=False)}}]},
        request=httpx.Request("POST", "https://api.deepseek.com/chat/completions"),
    )


def test_deepseek_retries_transient_503(monkeypatch):
    calls = []

    def fake_post(*args, **kwargs):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(
                503,
                text="temporarily unavailable",
                request=httpx.Request("POST", "https://api.deepseek.com/chat/completions"),
            )
        return _response({
            "is_threat": False,
            "confidence": 0.98,
            "reason": "benign",
            "evidence": [],
        })

    monkeypatch.setattr(httpx, "post", fake_post)
    client = DeepSeekClient("primary", None, "deepseek-flash", retry_backoff_seconds=0)
    result = client.classify(EmailDocument(subject="Hi", text="hello"))

    assert result.category == ThreatCategory.BENIGN
    assert len(calls) == 2


def test_deepseek_uses_secondary_key_after_primary_failure(monkeypatch):
    seen_auth = []

    def fake_post(*args, **kwargs):
        auth = kwargs["headers"]["Authorization"]
        seen_auth.append(auth)
        if auth.endswith("primary"):
            return httpx.Response(
                401,
                text="bad key",
                request=httpx.Request("POST", "https://api.deepseek.com/chat/completions"),
            )
        return _response({
            "is_threat": False,
            "confidence": 0.99,
            "reason": "benign",
            "evidence": [],
        })

    monkeypatch.setattr(httpx, "post", fake_post)
    client = DeepSeekClient("primary", "secondary", "deepseek-flash", retry_backoff_seconds=0)
    result = client.classify(EmailDocument(subject="Hi", text="hello"))

    assert result.category == ThreatCategory.BENIGN
    assert seen_auth == ["Bearer primary", "Bearer secondary"]


def test_invalid_ai_response_falls_back_without_losing_delivery():
    def fake_post(*args, **kwargs):
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "not-json"}}]},
            request=httpx.Request("POST", "https://api.deepseek.com/chat/completions"),
        )

    monkeypatch = __import__("pytest").MonkeyPatch()
    monkeypatch.setattr(httpx, "post", fake_post)
    try:
        client = DeepSeekClient("primary", None, "deepseek-flash", retry_backoff_seconds=0)
        result = client.classify(EmailDocument(subject="Hello", text="normal text"))
        assert result.source == "FALLBACK"
        assert result.category == ThreatCategory.BENIGN
        decision = PolicyEngine(GatewaySettings()).decide(result)
        assert decision.action == Action.DELIVER
        assert decision.review is True
    finally:
        monkeypatch.undo()


def test_fallback_strong_threat_is_alerted_and_reviewed():
    classification = Classification(
        category=ThreatCategory.TECHNOGENIC,
        is_threat=True,
        confidence=0.88,
        source="FALLBACK",
    )
    decision = PolicyEngine(GatewaySettings()).decide(classification)
    assert decision.action == Action.DELIVER_AND_ALERT
    assert decision.review is True
