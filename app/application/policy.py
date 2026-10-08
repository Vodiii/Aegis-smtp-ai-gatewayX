from __future__ import annotations

from app.domain.models import Action, Classification, GatewaySettings, PolicyDecision, ThreatCategory


class PolicyEngine:
    def __init__(self, settings: GatewaySettings) -> None:
        self.settings = settings

    def decide(self, classification: Classification) -> PolicyDecision:
        if classification.category == ThreatCategory.BENIGN or not classification.is_threat:
            return PolicyDecision(
                action=Action.DELIVER,
                category=classification.category,
                confidence=classification.confidence,
                review=classification.source == "FALLBACK",
                reason=(
                    "BENIGN/non-threat classification"
                    if classification.source != "FALLBACK"
                    else "AI unavailable; delivered to original recipients and flagged for manual review"
                ),
            )

        threshold = {
            ThreatCategory.TERRORISM: self.settings.terrorism_threshold,
            ThreatCategory.TECHNOGENIC: self.settings.technogenic_threshold,
            ThreatCategory.ILLEGAL: self.settings.illegal_threshold,
            ThreatCategory.OTHER_THREAT: self.settings.other_threat_threshold,
        }.get(classification.category, 1.0)

        destination = {
            ThreatCategory.TERRORISM: self.settings.terrorism_destination,
            ThreatCategory.TECHNOGENIC: self.settings.technogenic_destination,
            ThreatCategory.ILLEGAL: self.settings.illegal_destination,
            ThreatCategory.OTHER_THREAT: self.settings.other_threat_destination,
        }.get(classification.category)

        if destination:
            below_threshold = classification.confidence < threshold
            review = below_threshold or classification.source == "FALLBACK"
            threshold_note = (
                f"confidence {classification.confidence:.2f} below review threshold {threshold:.2f}"
                if below_threshold
                else f"confidence {classification.confidence:.2f} meets threshold {threshold:.2f}"
            )
            source_note = "fallback classification; manual review recommended" if classification.source == "FALLBACK" else "AI classification"
            return PolicyDecision(
                action=Action.DELIVER_AND_ALERT,
                category=classification.category,
                confidence=classification.confidence,
                destination=destination,
                review=review,
                reason=(
                    f"Threat classified as {classification.category.value}; {threshold_note}; {source_note}. "
                    "Deliver to original recipients and copy to alert mailbox."
                ),
            )

        return PolicyDecision(
            action=Action.DELIVER,
            category=classification.category,
            confidence=classification.confidence,
            review=True,
            reason="Threat category has no configured alert destination; deliver to original recipients and flag for review",
        )
