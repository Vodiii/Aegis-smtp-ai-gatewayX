from __future__ import annotations

import re

from app.domain.models import EmailDocument, ThreatCategory

# This policy is deliberately narrow. It resolves only two recurring overlaps seen
# in the 70-case regression suite without replacing the AI classifier.
_DATA_OR_REPUTATION_PATTERN = re.compile(
    r"(?:залью|выложу|опубликую|распространю|слив(?:ать|ом)?|опубликовать)"
    r".{0,100}(?:переписк|фото|скриншот|личн(?:ые|ых)\s+данн|данн|репутац|информац)"
    r"|(?:post|publish|leak|upload|release|share)"
    r".{0,100}(?:photos|pictures|messages|chats|screenshots|personal\s+data|data|information|reputation)",
    re.IGNORECASE,
)
_CYBER_OR_VIRUS_PATTERN = re.compile(
    r"(?:взлом|взломаем|вирус|вредоносн|кибератак|кибер\s+атак|хакн|атакуем\s+систем"
    r"|hack|hacking|malware|virus|cyberattack|cyber\s+attack)"
    r"",
    re.IGNORECASE,
)
_EXPLICIT_TECH_EVENT_PATTERN = re.compile(
    r"(?:авар(?:ия|ии|ию|ией)|взрыв|утечк|выброс|пожар|обрушен|радиаци|хлор|"
    r"затоплен|разрушен|отрав(?:им|ить)\s+(?:водозабор|вод[ау])|энергосет|гэс|аэс|"
    r"промышленн(?:ый|ого|ом)\s+объект|flood|flooding|"
    r"cause\s+(?:an?\s+)?outage|power\s+grid\s+(?:failure|outage)|"
    r"physical\s+damage)",
    re.IGNORECASE,
)
_PHYSICAL_ILLEGAL_PATTERN = re.compile(
    r"(?:убью|убить|покалеч|причиню\s+вред|нанесу\s+вред|похищ|подожг|ограб|украд|"
    r"проникн|шантаж.*(?:деньг|заплат)|вымог)",
    re.IGNORECASE,
)
_TRANSPORT_EXPLOSIVE_PATTERN = re.compile(
    r"(?:метро|станц(?:ия|ии|ию)|subway|underground|metro)"
    r".{0,120}(?:бомб|взрывчат|взрыв(?:ом|чатк|чат)|explosive|bomb)"
    r"|(?:бомб|взрывчат|взрыв(?:ом|чатк|чат)|explosive|bomb)"
    r".{0,120}(?:метро|станц(?:ия|ии|ию)|subway|underground|metro)",
    re.IGNORECASE,
)
_TERRORISM_MASS_ATTACK_PATTERN = re.compile(
    r"(?:огненн\w*\s+атак\w*|больш\w*\s+огненн\w*\s+атак\w*|"
    r"атака\s+на\s+(?:наши|нескольк\w*)\s+цел\w*|"
    r"массов\w*\s+(?:жертв|напад)\w*)",
    re.IGNORECASE,
)
_TERRORISM_INTENT_PATTERN = re.compile(
    r"террор|террорист|terrorist|terrorism|"
    r"заложник|hostage|"
    r"требовани|требуем|переведите|заплат|рубл|pay(?:ment)?|million|"
    r"массов(?:ые|ых)\s+(?:жертв|убийств|напад)|mass\s+(?:casualt|violence)|"
    r"призыва(?:ем|ю)?\s+к\s+насилию|call\s+for\s+violence",
    re.IGNORECASE,
)


def apply_category_policy(
    email: EmailDocument,
    category: ThreatCategory,
) -> tuple[ThreatCategory, str | None]:
    """Apply narrow, deterministic category precedence after AI classification.

    The policy never changes BENIGN, never removes a threat, and never creates a
    new AI call. It only corrects two high-confidence taxonomy overlaps:
    data/reputation disclosure and cyber/virus actions without a physical
    technogenic mechanism.
    """
    if category == ThreatCategory.ILLEGAL:
        text = f"{email.subject}\n{email.text}"
        if _DATA_OR_REPUTATION_PATTERN.search(text) and not _PHYSICAL_ILLEGAL_PATTERN.search(text):
            return ThreatCategory.OTHER_THREAT, "category policy: data/reputation threat takes precedence over generic ILLEGAL"

    text = f"{email.subject}\n{email.text}"

    if category == ThreatCategory.TECHNOGENIC:
        if _CYBER_OR_VIRUS_PATTERN.search(text) and not _EXPLICIT_TECH_EVENT_PATTERN.search(text):
            return ThreatCategory.OTHER_THREAT, "category policy: cyber/virus vector without explicit physical technogenic event is OTHER_THREAT"

    # Regression boundary from the agreed test taxonomy: an explosive hazard
    # in metro/transport without explicit terrorist intent is TECHNOGENIC.
    # A message that adds demands, hostage-taking, mass-casualty intent, or
    # explicit terrorist context remains TERRORISM. This does not create an AI call.
    if category == ThreatCategory.TERRORISM:
        if (_TRANSPORT_EXPLOSIVE_PATTERN.search(text)
                and not _TERRORISM_INTENT_PATTERN.search(text)):
            return ThreatCategory.TECHNOGENIC, "category policy: transport explosive hazard without explicit terrorist intent is TECHNOGENIC"

    # A broad/mass attack formulation is more specific than a generic ILLEGAL
    # label. Keep this narrow so ordinary personal arson/threats remain ILLEGAL.
    if category == ThreatCategory.ILLEGAL:
        if _TERRORISM_MASS_ATTACK_PATTERN.search(text) and not _PHYSICAL_ILLEGAL_PATTERN.search(text):
            return ThreatCategory.TERRORISM, "category policy: broad/mass attack intent takes precedence over generic ILLEGAL"

    return category, None
