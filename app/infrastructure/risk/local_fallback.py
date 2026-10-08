from __future__ import annotations

import re
from app.domain.models import Classification, EmailDocument, GatewaySettings, ThreatCategory
from app.infrastructure.risk.engine import RiskEngine
from app.infrastructure.risk.normalizer import normalize

# Deliberate violent/explosive intent is treated as terrorism in the
# emergency fallback because there is no AI available to resolve intent.
_TERRORISM_INTENT = re.compile(
    r"\b(взорву|взорвать|подорву|подорвать)\b",
    re.IGNORECASE,
)
_TERRORISM_PATTERNS = re.compile(
    r"\b(теракт\w*|террорист\w*|заложник\w*|бомб\w*|заминиров\w*|диверс\w*)\b",
    re.IGNORECASE,
)
_TECHNOGENIC_PATTERNS = re.compile(
    r"\b(авар\w*|взрыв\w*|утеч\w*|выброс\w*|радиац\w*|пожар\w*|обруш\w*|техногенн\w*|промышленн\w*)\b",
    re.IGNORECASE,
)
_ILLEGAL_PATTERNS = re.compile(
    r"\b(взлом\w*|ограб\w*|похит\w*|краж\w*|поджог\w*|проник\w*|украд\w*|незакон\w*|вредоносн\w*)\b",
    re.IGNORECASE,
)
_OTHER_PATTERNS = re.compile(
    r"\b(убью|убить|убийств\w*|причин\w*\s+вред|нанес\w*\s+вред|расправ\w*|угрож\w*)\b",
    re.IGNORECASE,
)


def classify_local_fallback(
    email: EmailDocument,
    reason: str,
    settings: GatewaySettings | None = None,
) -> Classification:
    settings = settings or GatewaySettings()
    engine = RiskEngine(settings)
    risk = engine.assess(email)
    text = normalize(f"{email.subject}\n{email.text}").normalized

    # If Risk Engine sees strong benign context, retain benign classification.
    # This prevents an emergency fallback from flagging news/history merely
    # because they contain words such as "террорист" or "взрыв".
    benign_context = any(
        marker in text
        for marker in (
            "вчера в новостях",
            "историческая статья",
            "в прошлом",
            "произошел",
            "произошла",
            "произошло",
            "учебный материал",
            "это вымышленное",
        )
    )
    if benign_context and not risk.phrases and not risk.obfuscation_detected:
        return Classification(
            category=ThreatCategory.BENIGN,
            is_threat=False,
            confidence=0.20,
            reason=f"Local emergency fallback considered the message benign in context. {reason}",
            evidence=risk.keywords + risk.phrases,
            source="FALLBACK",
            threat_confidence=0.20,
        )

    category: ThreatCategory | None = None
    if _TERRORISM_PATTERNS.search(text) or _TERRORISM_INTENT.search(text):
        category = ThreatCategory.TERRORISM
    elif _ILLEGAL_PATTERNS.search(text):
        category = ThreatCategory.ILLEGAL
    elif _OTHER_PATTERNS.search(text):
        category = ThreatCategory.OTHER_THREAT
    elif _TECHNOGENIC_PATTERNS.search(text):
        category = ThreatCategory.TECHNOGENIC

    # A high local risk with no category-specific match is still a threat;
    # OTHER_THREAT is the safest catch-all when AI is unavailable.
    if category is None and risk.requires_ai and risk.score >= settings.risk_ai_threshold:
        category = ThreatCategory.OTHER_THREAT

    if category is None:
        return Classification(
            category=ThreatCategory.BENIGN,
            is_threat=False,
            confidence=max(0.20, min(1.0, 1.0 - risk.score)),
            reason=f"Local emergency fallback found no credible threat signal. {reason}",
            evidence=risk.keywords + risk.phrases,
            source="FALLBACK",
            threat_confidence=max(0.20, min(1.0, risk.score)),
        )

    confidence = max(0.82, min(0.95, 0.80 + risk.score * 0.15))
    return Classification(
        category=category,
        is_threat=True,
        confidence=confidence,
        reason=f"Local emergency fallback detected a threat pattern. {reason}",
        evidence=list(dict.fromkeys(risk.keywords + risk.phrases)),
        source="FALLBACK",
        threat_confidence=confidence,
    )
