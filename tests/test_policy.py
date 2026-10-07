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


def test_low_confidence_threat_still_alerts_and_marks_review():
    result = PolicyEngine(GatewaySettings()).decide(
        Classification(category=ThreatCategory.ILLEGAL, is_threat=True, confidence=0.40)
    )
    assert result.action == Action.DELIVER_AND_ALERT
    assert result.destination == "alerts-illegal@local.test"
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



def test_terrorism_threshold_0_72_alerts():
    result = PolicyEngine(GatewaySettings()).decide(
        Classification(category=ThreatCategory.TERRORISM, is_threat=True, confidence=0.72)
    )
    assert result.action == Action.DELIVER_AND_ALERT
    assert result.destination == "alerts-terrorism@local.test"
    assert result.review is False


def test_terrorism_below_threshold_still_alerts_and_marks_review():
    result = PolicyEngine(GatewaySettings()).decide(
        Classification(category=ThreatCategory.TERRORISM, is_threat=True, confidence=0.65)
    )
    assert result.action == Action.DELIVER_AND_ALERT
    assert result.destination == "alerts-terrorism@local.test"
    assert result.review is True


def test_threat_is_alerted_even_when_confidence_is_low():
    from app.application.policy import PolicyEngine
    from app.domain.models import Classification, GatewaySettings, ThreatCategory, Action

    decision = PolicyEngine(GatewaySettings()).decide(
        Classification(
            category=ThreatCategory.TERRORISM,
            is_threat=True,
            confidence=0.41,
            threat_confidence=0.41,
            reason="credible threat",
        )
    )

    assert decision.action == Action.DELIVER_AND_ALERT
    assert decision.review is True
