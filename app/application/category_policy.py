from __future__ import annotations

import re

from app.domain.models import EmailDocument, ThreatCategory

# Эта политика намеренно узкая. Она устраняет только два повторявшихся пересечения категорий
# из регрессионного набора на 70 случаев и не заменяет классификатор ИИ.
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
_EXTORTION_PATTERN = re.compile(
    r"(?:заплат(?:ишь|и|ить)|плат(?:и|ить|ишь)|отда(?:шь|й)|pay|payment).{0,100}(?:молчани|иначе|otherwise|else)|"
    r"(?:за\s+молчан|for\s+silence).{0,100}(?:узнает|learns|finds\s+out|otherwise|else)",
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
    """Применить узкие детерминированные правила категорий после классификации ИИ.

    Политика не изменяет BENIGN, не удаляет угрозы и не создаёт новые вызовы ИИ.
    Она исправляет только два пересечения таксономии с высокой уверенностью:
    угрозы раскрытия данных/репутации и кибердействия/вирусы без явного
    физического техногенного механизма.
    """
    text = f"{email.subject}\n{email.text}"

    # Явное вымогательство или шантаж относится к ILLEGAL, кроме более узкого сценария
    # угрозы раскрыть данные или навредить репутации: по нашей таксономии он намеренно
    # классифицируется как OTHER_THREAT.
    if category == ThreatCategory.OTHER_THREAT:
        if _EXTORTION_PATTERN.search(text) and not _DATA_OR_REPUTATION_PATTERN.search(text):
            return ThreatCategory.ILLEGAL, "category policy: explicit extortion/blackmail takes precedence over generic OTHER_THREAT"

    if category == ThreatCategory.ILLEGAL:
        if _DATA_OR_REPUTATION_PATTERN.search(text) and not _PHYSICAL_ILLEGAL_PATTERN.search(text):
            return ThreatCategory.OTHER_THREAT, "category policy: data/reputation threat takes precedence over generic ILLEGAL"

    if category == ThreatCategory.TECHNOGENIC:
        if _CYBER_OR_VIRUS_PATTERN.search(text) and not _EXPLICIT_TECH_EVENT_PATTERN.search(text):
            return ThreatCategory.OTHER_THREAT, "category policy: cyber/virus vector without explicit physical technogenic event is OTHER_THREAT"

    # Граница из согласованной тестовой таксономии: угроза взрыва в метро или транспорте
    # без явного террористического намерения относится к TECHNOGENIC.
    # Если в сообщении есть требования, захват заложников, намерение вызвать массовые жертвы
    # или явный террористический контекст, категория остаётся TERRORISM. Новый вызов ИИ не выполняется.
    if category == ThreatCategory.TERRORISM:
        if (_TRANSPORT_EXPLOSIVE_PATTERN.search(text)
                and not _TERRORISM_INTENT_PATTERN.search(text)):
            return ThreatCategory.TECHNOGENIC, "category policy: transport explosive hazard without explicit terrorist intent is TECHNOGENIC"

    # Формулировка о широкомасштабном или массовом нападении конкретнее общей категории.
    # Применяем правило и к OTHER_THREAT: модель может распознать угрозу, но выбрать слишком общую категорию.
    # Личные угрозы и обычные поджоги сохраняют свою категорию.
    if category in {ThreatCategory.ILLEGAL, ThreatCategory.OTHER_THREAT}:
        if _TERRORISM_MASS_ATTACK_PATTERN.search(text) and not _PHYSICAL_ILLEGAL_PATTERN.search(text):
            return ThreatCategory.TERRORISM, "category policy: broad/mass attack intent takes precedence over generic threat category"

    return category, None
