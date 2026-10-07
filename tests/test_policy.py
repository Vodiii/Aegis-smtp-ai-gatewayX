from app.application.policy import PolicyEngine
from app.domain.models import Classification, GatewaySettings, Action, ThreatCategory


def test_benign_delivers_unchanged():
    result = PolicyEngine(GatewaySettings()).decide(
        Classification(category=ThreatCategory.BENIGN, is_threat=False, confidence=0.99)
    )
    assert result.action == Action.DELIVER
    assert result.review is False


def test_high_confidence_threat_is_delivered_and_alerted():
    result = PolicyEngine(GatewaySettings()).decide(
        Classification(category=ThreatCategory.TERRORISM, is_threat=True, confidence=0.95)
    )
    assert result.action == Action.DELIVER_AND_ALERT
    assert result.destination == "alerts-terrorism@local.test"


def test_low_confidence_threat_delivers_for_review():
    result = PolicyEngine(GatewaySettings()).decide(
        Classification(category=ThreatCategory.ILLEGAL, is_threat=True, confidence=0.40)
    )
    assert result.action == Action.DELIVER
    assert result.review is True


def test_fallback_threat_is_delivered_and_alerted_when_confident():
    result = PolicyEngine(GatewaySettings()).decide(
        Classification(
            category=ThreatCategory.TECHNOGENIC,
            is_threat=True,
            confidence=0.88,
            source="FALLBACK",
        )
    )
    assert result.action == Action.DELIVER_AND_ALERT
    assert result.review is False

