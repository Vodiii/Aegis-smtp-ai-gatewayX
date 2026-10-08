import httpx

from app.domain.models import EmailDocument, ThreatCategory
from app.infrastructure.deepseek.client import DeepSeekClient


def _fail(*args, **kwargs):
    raise httpx.ConnectError(
        "DeepSeek unavailable",
        request=httpx.Request("POST", "https://api.deepseek.com/chat/completions"),
    )


def test_old_bug_fallback_detects_deliberate_explosion_threat(monkeypatch):
    monkeypatch.setattr(httpx, "post", _fail)
    client = DeepSeekClient("primary", "secondary", "deepseek-flash", max_retries=0)
    for text in ("Завтра в 12:00 взорву офис.", "Завтра взорвать офис", "Подорву здание завтра"):
        result = client.classify(EmailDocument(subject="Угроза", text=text))
        assert result.source == "FALLBACK", text
        assert result.is_threat is True, text
        assert result.category == ThreatCategory.TERRORISM, text


def test_fallback_keeps_safety_context_for_unintentional_explosion(monkeypatch):
    monkeypatch.setattr(httpx, "post", _fail)
    client = DeepSeekClient("primary", None, "deepseek-flash", max_retries=0)
    result = client.classify(EmailDocument(subject="Предупреждение", text="Завтра ожидается взрыв оборудования."))
    assert result.is_threat is True
    assert result.category == ThreatCategory.TECHNOGENIC
