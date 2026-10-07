import json

import httpx

from app.domain.models import EmailDocument, ThreatCategory
from app.infrastructure.deepseek.client import DeepSeekClient


def test_benign_conflict_triggers_threat_adjudication_then_category(monkeypatch):
    responses = iter([
        {
            "is_threat": False,
            "confidence": 0.72,
            "reason": "first pass",
            "evidence": [],
        },
        {
            "is_threat": True,
            "confidence": 0.90,
            "reason": "direct threat indicators",
            "evidence": ["угроза взрыва"],
        },
        {
            "category": "TERRORISM",
            "confidence": 0.92,
            "reason": "terrorism threat",
            "evidence": ["захват заложников"],
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
    result = client.classify(EmailDocument(
        subject="Предупреждение",
        text="В сообщении содержится прямая угроза взрыва и захвата заложников с целью массового нападения.",
    ))

    assert result.category == ThreatCategory.TERRORISM
    assert result.source == "AI_TWO_STAGE"
    assert result.threat_confidence == 0.90
    assert "угроза взрыва" in result.evidence


def test_adjudication_false_keeps_non_threat(monkeypatch):
    responses = iter([
        {"is_threat": False, "confidence": 0.72, "reason": "first pass", "evidence": []},
        {"is_threat": False, "confidence": 0.95, "reason": "quoted news", "evidence": []},
    ])

    def fake_post(*args, **kwargs):
        body = next(responses)
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": json.dumps(body)}}]},
            request=httpx.Request("POST", "https://api.deepseek.com/chat/completions"),
        )

    monkeypatch.setattr(httpx, "post", fake_post)
    client = DeepSeekClient("primary", None, "deepseek-flash")
    result = client.classify(EmailDocument(
        subject="Новость", text="Отчёт о прошлом событии и словах, процитированных в новости.",
    ))

    assert result.category == ThreatCategory.BENIGN
    assert result.is_threat is False


def test_technogenic_current_warning_is_treated_as_threat(monkeypatch):
    responses = iter([
        {
            "is_threat": False,
            "confidence": 0.82,
            "reason": "first pass interpreted this as a report",
            "evidence": [],
        },
        {
            "is_threat": True,
            "confidence": 0.91,
            "reason": "current/future industrial accident warning",
            "evidence": ["возможной техногенной аварии", "риск"],
        },
        {
            "category": "TECHNOGENIC",
            "confidence": 0.90,
            "reason": "industrial accident risk",
            "evidence": ["техногенной аварии"],
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
    result = client.classify(EmailDocument(
        subject="Опасность на производстве",
        text="Поступило предупреждение о возможной техногенной аварии на предприятии из-за неисправности оборудования. Риск относится к промышленной инфраструктуре.",
    ))

    assert result.category == ThreatCategory.TECHNOGENIC
    assert result.is_threat is True
    assert result.threat_confidence == 0.91
