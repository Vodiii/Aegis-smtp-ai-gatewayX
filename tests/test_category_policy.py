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


def test_broad_fire_attack_overrides_generic_other_threat():
    email = EmailDocument(text="Скоро всё сгорит. Готовьтесь к большой огненной атаке на наши цели.")
    category, reason = apply_category_policy(email, ThreatCategory.OTHER_THREAT)
    assert category == ThreatCategory.TERRORISM
    assert reason


def test_personal_arson_does_not_become_terrorism():
    email = EmailDocument(text="Подожгу твою машину, если не заплатишь.")
    category, reason = apply_category_policy(email, ThreatCategory.ILLEGAL)
    assert category == ThreatCategory.ILLEGAL
    assert reason is None


def test_explicit_silence_extortion_overrides_generic_other_threat():
    email = EmailDocument(text="Заплатишь мне за молчание, иначе сосед узнает всё.")
    category, reason = apply_category_policy(email, ThreatCategory.OTHER_THREAT)
    assert category == ThreatCategory.ILLEGAL
    assert reason


def test_data_disclosure_extortion_remains_other_threat():
    email = EmailDocument(text="Залью твои переписки и фото в сеть, если не заплатишь.")
    category, reason = apply_category_policy(email, ThreatCategory.ILLEGAL)
    assert category == ThreatCategory.OTHER_THREAT
    assert reason


def test_public_explosive_ultimatum_is_terrorism_even_if_ai_says_technogenic():
    email = EmailDocument(text="Завтра в 12:00 в торговом центре произойдёт взрыв, если наши требования не будут выполнены.")
    category, reason = apply_category_policy(email, ThreatCategory.TECHNOGENIC)
    assert category == ThreatCategory.TERRORISM
    assert reason


def test_obfuscated_public_explosive_ultimatum_is_terrorism():
    email = EmailDocument(text="Мы в3рвём ТЦ завтра в 12:00, если не выплатят деньги.")
    category, reason = apply_category_policy(email, ThreatCategory.OTHER_THREAT)
    assert category == ThreatCategory.TERRORISM
    assert reason


def test_grid_outage_is_technogenic_even_if_ai_says_other_threat():
    email = EmailDocument(text="Мы отключим энергосеть города в ближайшие дни. Готовьтесь к темноте.")
    category, reason = apply_category_policy(email, ThreatCategory.OTHER_THREAT)
    assert category == ThreatCategory.TECHNOGENIC
    assert reason


def test_municipal_water_intake_poisoning_is_technogenic():
    email = EmailDocument(text="Мы отравим водозабор города в ближайшие сутки. Не пейте воду.")
    category, reason = apply_category_policy(email, ThreatCategory.OTHER_THREAT)
    assert category == ThreatCategory.TECHNOGENIC
    assert reason


def test_direct_killing_threat_is_illegal_even_if_ai_says_other_threat():
    email = EmailDocument(text="Найду тебя и убью. Это не шутка.")
    category, reason = apply_category_policy(email, ThreatCategory.OTHER_THREAT)
    assert category == ThreatCategory.ILLEGAL
    assert reason


def test_english_threat_to_family_is_illegal():
    email = EmailDocument(text="We will hurt your family if you don't pay.")
    category, reason = apply_category_policy(email, ThreatCategory.OTHER_THREAT)
    assert category == ThreatCategory.ILLEGAL
    assert reason


def test_customer_data_disclosure_is_other_threat_even_if_ai_says_illegal():
    email = EmailDocument(text="Мы взломаем систему и выложим данные клиентов в открытый доступ.")
    category, reason = apply_category_policy(email, ThreatCategory.ILLEGAL)
    assert category == ThreatCategory.OTHER_THREAT
    assert reason


def test_benign_category_is_never_changed_by_category_policy():
    email = EmailDocument(text="Вчера в центре города произошёл теракт.")
    category, reason = apply_category_policy(email, ThreatCategory.BENIGN)
    assert category == ThreatCategory.BENIGN
    assert reason is None


def test_mass_casualty_intent_has_priority_over_generic_violence_terms():
    email = EmailDocument(text="Готовим массовые жертвы. Наши требования будут опубликованы позже.")
    category, reason = apply_category_policy(email, ThreatCategory.ILLEGAL)
    assert category == ThreatCategory.TERRORISM
    assert reason


def test_implied_death_threat_is_illegal():
    email = EmailDocument(text="Если опубликуешь эту статью, она станет последней в твоей жизни.")
    category, reason = apply_category_policy(email, ThreatCategory.OTHER_THREAT)
    assert category == ThreatCategory.ILLEGAL
    assert reason
