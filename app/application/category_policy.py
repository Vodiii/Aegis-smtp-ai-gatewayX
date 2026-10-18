from __future__ import annotations

import re

from app.domain.models import EmailDocument, ThreatCategory

# Эти правила применяются только к уже обнаруженным угрозам.
# Они разрешают пересечения категорий из согласованной таксономии и не заменяют AI.
_DATA_OR_REPUTATION_PATTERN = re.compile(
    r"(?:заль\w*|вылож\w*|опублику\w*|распростран\w*|слив\w*|разошл\w*)"
    r".{0,120}(?:переписк\w*|фото\w*|скриншот\w*|личн\w*\s+данн\w*|данн\w*|репутац\w*|информац\w*|клиент\w*)"
    r"|(?:post|publish|leak|upload|release|share|expose)"
    r".{0,120}(?:photos|pictures|messages|chats|screenshots|personal\s+data|customer\s+data|data|information|reputation)",
    re.IGNORECASE,
)
_CYBER_OR_VIRUS_PATTERN = re.compile(
    r"(?:взлом\w*|вирус\w*|вредоносн\w*|кибератак\w*|кибер\s*атак\w*|хак\w*|"
    r"hack\w*|malware|virus|cyberattack|cyber\s+attack)",
    re.IGNORECASE,
)
_EXPLICIT_TECH_EVENT_PATTERN = re.compile(
    r"(?:авари\w*|взрыв\w*|утечк\w*|выброс\w*|пожар\w*|обрушен\w*|радиаци\w*|хлор\w*|"
    r"затоплен\w*|энергосет\w*|энергосистем\w*|отключ\w*.{0,40}(?:энергосет|электр|power|grid)|"
    r"гэс\b|аэс\b|промышленн\w*\s+объект\w*|химзавод\w*|химическ\w*\s+утечк\w*|"
    r"flood\w*|chemical\s+leak|power\s+grid|grid\s+(?:failure|outage)|"
    r"cause\s+(?:an?\s+)?outage|physical\s+damage)",
    re.IGNORECASE,
)
_EXTORTION_PATTERN = re.compile(
    r"(?:заплат\w*|плат\w*|отда\w*|pay\w*|payment).{0,120}(?:молчан\w*|иначе|узнает|otherwise|else|finds\s+out)|"
    r"(?:за\s+молчан\w*|for\s+silence).{0,120}(?:узнает|иначе|learns|finds\s+out|otherwise|else)",
    re.IGNORECASE,
)
_PHYSICAL_ILLEGAL_PATTERN = re.compile(
    r"(?:убью|убить|убьем|убьём|убьет|убьёт|убиваю|покалеч\w*|причин\w*\s+вред|нанес\w*\s+вред|похищ\w*|подожг\w*|"
    r"ограб\w*|украд\w*|проникн\w*|вымог\w*|шантаж\w*|"
    r"kill\w*|hurt\w*|injur\w*|kidnap\w*|burn\s+down|rob\w*|steal\w*|harm\w*|"
    r"последн\w*.{0,50}в\s+твоей\s+жизни|last\s+.{0,40}of\s+your\s+life|"
    r"пожалеешь.{0,80}(?:работаешь|судь\w*)|мы\s+тебя\s+достанем)",
    re.IGNORECASE,
)
_TRANSPORT_EXPLOSIVE_PATTERN = re.compile(
    r"(?:метро|станц\w*|subway|underground|metro|транспорт\w*)"
    r".{0,140}(?:бомб\w*|взрывчат\w*|взрыв\w*|explosive\w*|bomb\w*)"
    r"|(?:бомб\w*|взрывчат\w*|взрыв\w*|explosive\w*|bomb\w*)"
    r".{0,140}(?:метро|станц\w*|subway|underground|metro|транспорт\w*)",
    re.IGNORECASE,
)
_TERRORISM_INTENT_PATTERN = re.compile(
    r"террор\w*|terroris\w*|заложник\w*|hostage\w*|"
    r"требован\w*|требуем|перевед\w*|заплат\w*|выплат\w*|pay\w*|million|"
    r"массов\w*\s+(?:жертв\w*|убийств\w*|напад\w*)|mass\s+(?:casualt\w*|violence)|"
    r"призыва\w*\s+к\s+насилию|call\s+for\s+violence|"
    r"все\s+объект\w*\s+буд\w*\s+уничтож\w*|multiple\s+targets",
    re.IGNORECASE,
)
_BROAD_MASS_ATTACK_PATTERN = re.compile(
    r"(?:огненн\w*\s+атак\w*|больш\w*\s+огненн\w*\s+атак\w*|"
    r"атак\w*.{0,80}(?:наши|нескольк\w*)\s+цел\w*|"
    r"массов\w*\s+(?:жертв\w*|напад\w*|убийств\w*)|"
    r"захват\w*.{0,80}школ\w*.{0,80}заложник\w*|"
    r"призыва\w*\s+к\s+насилию|все\s+объект\w*\s+буд\w*\s+уничтож\w*|"
    r"broad\s+attack|mass\s+casualt\w*|hostage\w*\s+taking)",
    re.IGNORECASE,
)
_PUBLIC_EXPLOSIVE_DEMAND_PATTERN = re.compile(
    r"(?:торгов\w*\s+центр\w*|\bтц\b|метро|школ\w*|стадион\w*|"
    r"shopping\s+cent\w*|subway|school|public\s+venue)"
    r".{0,180}(?:взрыв\w*|в[з3]рв\w*|бомб\w*|взрывчат\w*|detonat\w*|bomb\w*|explos\w*)"
    r"|(?:взрыв\w*|в[з3]рв\w*|бомб\w*|взрывчат\w*|detonat\w*|bomb\w*|explos\w*)"
    r".{0,180}(?:торгов\w*\s+центр\w*|\bтц\b|метро|школ\w*|стадион\w*|shopping\s+cent\w*|subway|school)",
    re.IGNORECASE,
)


def apply_category_policy(
    email: EmailDocument,
    category: ThreatCategory,
) -> tuple[ThreatCategory, str | None]:
    """Согласовать категорию обнаруженной угрозы с правилами таксономии.

    BENIGN не меняется. Для угроз приоритеты таковы: явная массовая атака/терроризм,
    затем конкретная физическая техногенная угроза, затем личное преступление;
    раскрытие данных и репутационные угрозы относятся к OTHER_THREAT.
    """
    if category == ThreatCategory.BENIGN:
        return category, None

    text = f"{email.subject}\n{email.text}"

    # Ультиматум с бомбой/взрывом в общественном месте относится к TERRORISM.
    if _PUBLIC_EXPLOSIVE_DEMAND_PATTERN.search(text) and _TERRORISM_INTENT_PATTERN.search(text):
        if category != ThreatCategory.TERRORISM:
            return ThreatCategory.TERRORISM, "category policy: public-target explosive threat with coercive/terrorist intent is TERRORISM"
        return category, None

    # Массовое насилие и захват заложников важнее общей категории угрозы.
    if _BROAD_MASS_ATTACK_PATTERN.search(text) and not _PHYSICAL_ILLEGAL_PATTERN.search(text):
        if category != ThreatCategory.TERRORISM:
            return ThreatCategory.TERRORISM, "category policy: explicit mass-attack/hostage intent is TERRORISM"
        return category, None

    # Угроза взрыва в транспорте без ультиматума или иных признаков террористического умысла
    # по принятой тестовой таксономии относится к TECHNOGENIC.
    if _TRANSPORT_EXPLOSIVE_PATTERN.search(text) and not _TERRORISM_INTENT_PATTERN.search(text):
        if category != ThreatCategory.TECHNOGENIC:
            return ThreatCategory.TECHNOGENIC, "category policy: transport explosive hazard without terrorist intent is TECHNOGENIC"
        return category, None

    # События на энергосетях, промышленных объектах и городском водозаборе — TECHNOGENIC.
    # Кибератака без явного физического последствия и утечка данных остаются OTHER_THREAT.
    public_water_poisoning = bool(re.search(
        r"(?:отрав\w*|poison\w*).{0,100}(?:водозабор\w*|водоснабжен\w*|water\s+supply)"
        r"|(?:водозабор\w*|водоснабжен\w*|water\s+supply).{0,100}(?:отрав\w*|poison\w*)",
        text, re.IGNORECASE,
    ))
    if _EXPLICIT_TECH_EVENT_PATTERN.search(text) or public_water_poisoning:
        if not (_CYBER_OR_VIRUS_PATTERN.search(text) and not _EXPLICIT_TECH_EVENT_PATTERN.search(text)):
            if category != ThreatCategory.TECHNOGENIC:
                return ThreatCategory.TECHNOGENIC, "category policy: explicit industrial/infrastructure physical hazard is TECHNOGENIC"
            return category, None

    # Раскрытие переписки, фото или клиентских данных — OTHER_THREAT, даже при требовании денег.
    if _DATA_OR_REPUTATION_PATTERN.search(text) and not _PHYSICAL_ILLEGAL_PATTERN.search(text):
        if category != ThreatCategory.OTHER_THREAT:
            return ThreatCategory.OTHER_THREAT, "category policy: data disclosure/reputation harm is OTHER_THREAT"

    # Конкретная личная угроза или вымогательство относится к ILLEGAL.
    if _PHYSICAL_ILLEGAL_PATTERN.search(text) or _EXTORTION_PATTERN.search(text):
        if category != ThreatCategory.ILLEGAL:
            return ThreatCategory.ILLEGAL, "category policy: direct personal criminal threat/extortion is ILLEGAL"

    # Кибердействие без явно описанного физического происшествия — OTHER_THREAT.
    if _CYBER_OR_VIRUS_PATTERN.search(text) and not _EXPLICIT_TECH_EVENT_PATTERN.search(text):
        if category != ThreatCategory.OTHER_THREAT:
            return ThreatCategory.OTHER_THREAT, "category policy: cyber/virus threat without explicit physical disaster is OTHER_THREAT"

    return category, None
