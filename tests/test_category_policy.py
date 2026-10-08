from app.application.category_policy import apply_category_policy
from app.domain.models import EmailDocument, ThreatCategory


def test_data_disclosure_overrides_generic_illegal():
    email = EmailDocument(text="Залью твои переписки и фото в сеть, если не заплатишь.")
    category, reason = apply_category_policy(email, ThreatCategory.ILLEGAL)
    assert category == ThreatCategory.OTHER_THREAT
    assert reason


def test_cyber_virus_without_physical_accident_is_other_threat():
    email = EmailDocument(text="Запущу вирус в систему водоснабжения города.")
    category, reason = apply_category_policy(email, ThreatCategory.TECHNOGENIC)
    assert category == ThreatCategory.OTHER_THREAT
    assert reason


def test_cyber_action_causing_physical_disaster_stays_technogenic():
    email = EmailDocument(text="Взломаем управление ГЭС и откроем затворы, чтобы затопить город.")
    category, reason = apply_category_policy(email, ThreatCategory.TECHNOGENIC)
    assert category == ThreatCategory.TECHNOGENIC
    assert reason is None


def test_physical_illegal_threat_stays_illegal():
    email = EmailDocument(text="Найду тебя и убью, если не вернёшь долг сегодня.")
    category, reason = apply_category_policy(email, ThreatCategory.ILLEGAL)
    assert category == ThreatCategory.ILLEGAL
    assert reason is None


def test_transport_explosive_without_terrorist_intent_is_technogenic():
    email = EmailDocument(text="В час пик в метро будет заложена взрывчатка.")
    category, reason = apply_category_policy(email, ThreatCategory.TERRORISM)
    assert category == ThreatCategory.TECHNOGENIC
    assert reason


def test_transport_bomb_with_payment_demand_stays_terrorism():
    email = EmailDocument(text="В метро заложена бомба. Переведите 5 миллионов рублей, иначе произойдёт взрыв.")
    category, reason = apply_category_policy(email, ThreatCategory.TERRORISM)
    assert category == ThreatCategory.TERRORISM
    assert reason is None


def test_broad_fire_attack_overrides_generic_illegal():
    email = EmailDocument(text="Скоро всё сгорит. Готовьтесь к большой огненной атаке на наши цели.")
    category, reason = apply_category_policy(email, ThreatCategory.ILLEGAL)
    assert category == ThreatCategory.TERRORISM
    assert reason


def test_personal_arson_does_not_become_terrorism():
    email = EmailDocument(text="Подожгу твою машину, если не заплатишь.")
    category, reason = apply_category_policy(email, ThreatCategory.ILLEGAL)
    assert category == ThreatCategory.ILLEGAL
    assert reason is None
