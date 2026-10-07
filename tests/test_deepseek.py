import json

import httpx

from app.domain.models import EmailDocument, ThreatCategory
from app.infrastructure.deepseek.client import DeepSeekClient


def test_deepseek_json_response(monkeypatch):
    def fake_post(*args, **kwargs):
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "category": "TECHNOGENIC",
                                    "is_threat": True,
                                    "confidence": 0.93,
                                    "reason": "credible accident threat",
                                    "evidence": ["взрыв на заводе"],
                                }
                            )
                        }
                    }
                ]
            },
            request=httpx.Request("POST", "https://api.deepseek.com/chat/completions"),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    client = DeepSeekClient("primary", None, "deepseek-flash")
    result = client.classify(EmailDocument(subject="test", text="text"))

    assert result.source == "AI"
    assert result.category == ThreatCategory.TECHNOGENIC
    assert result.confidence == 0.93


def test_no_api_key_returns_fallback_source():
    client = DeepSeekClient(None, None, "deepseek-flash")
    result = client.classify(
        EmailDocument(subject="", text="Завтра произойдет авария на заводе.")
    )
    assert result.source == "FALLBACK"
    assert result.category == ThreatCategory.BENIGN or result.category == ThreatCategory.TECHNOGENIC
