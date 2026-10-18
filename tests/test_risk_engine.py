from app.domain.models import EmailDocument, GatewaySettings
from app.infrastructure.risk.engine import RiskEngine
from app.infrastructure.risk.normalizer import normalize


def engine():
    return RiskEngine(GatewaySettings())


def test_obfuscated_variant_is_detected():
    result = normalize("B3pbIB завтра в 12:00")
    assert result.obfuscation_detected is True


def test_obvious_business_mail_can_bypass_ai():
    result = engine().assess(EmailDocument(subject="Отчет", text="Во вложении отчет по проекту и сроки поставки."))
    assert result.requires_ai is False


def test_threat_keyword_keeps_suspicious_benign_context_on_ai():
    result = engine().assess(EmailDocument(subject="Новость", text="Новостная заметка о расследовании прошлого теракта."))
    assert result.keywords
    assert result.requires_ai is True


def test_threat_phrase_requires_ai():
    result = engine().assess(EmailDocument(subject="Внимание", text="Завтра в 12:00 произойдет взрыв на объекте."))
    assert result.requires_ai is True
    assert result.score > 0


def test_obfuscated_threat_requires_ai():
    result = engine().assess(EmailDocument(subject="", text="B3pbIB завтра в 12:00 на объекте."))
    assert result.obfuscation_detected is True
    assert result.requires_ai is True


def test_normal_business_tracking_code_is_not_obfuscation():
    result = normalize("Обновить PRJ-1000 до пятницы")
    assert result.obfuscation_detected is False


def test_separator_obfuscation_is_escalated_to_ai():
    result = engine().assess(EmailDocument(subject="", text="в-з-р-ы-в на объекте завтра"))
    assert result.requires_ai is True
    assert "взрыв" in result.keywords


def test_business_identifier_with_digit_and_letter_is_not_obfuscation():
    from app.infrastructure.risk.normalizer import normalize

    result = normalize("[QA-1791429550-B001] Статус проекта")
    assert result.obfuscation_detected is False


def test_leetspeak_between_letters_is_obfuscation():
    from app.infrastructure.risk.normalizer import normalize

    result = normalize("B3pBI")
    assert result.obfuscation_detected is True


def test_char_model_signal_alone_escalates_to_ai():
    result = engine().assess(EmailDocument(subject="Предупреждение", text="Подготовлена атака с целью вызвать массовый страх и жертвы."))
    assert result.requires_ai is True
    assert result.char_probability >= 0.75



def test_explicit_safe_context_can_override_keyword_signal():
    cases = [
        ("Новости", "Вчера в центре города произошёл теракт. Все подробности уточняются следствием."),
        ("Новости", "Спецслужбы предотвратили крупный теракт. Об этом сообщил официальный представитель."),
        ("Книга", "Цитата из книги: «Я убью тебя», — сказал главный герой в финале."),
        ("Учёба", "Уничтожу экзамен — надо как следует подготовиться."),
        ("Дедлайны", "У меня дедлайны как у террориста — всё горит!"),
    ]
    for subject, text in cases:
        result = engine().assess(EmailDocument(subject=subject, text=text))
        assert result.requires_ai is False, (subject, text, result.reason)


def test_business_subject_does_not_override_threat_keywords():
    result = engine().assess(EmailDocument(
        subject="План аварии",
        text="Планируем аварию на ГЭС. Это приведёт к затоплению города.",
    ))
    assert result.requires_ai is True


def test_external_qa_threats_still_require_ai_and_ai_routing_is_reduced():
    import json
    from pathlib import Path

    cases = json.loads(
        (Path(__file__).resolve().parents[1] / "test-data" / "external_qa_suite.json").read_text(encoding="utf-8")
    )
    analyzer = engine()
    ai_count = 0
    for case in cases:
        result = analyzer.assess(EmailDocument(subject=case["subject"], text=case["body"]))
        if case["category"] != "BENIGN":
            assert result.requires_ai is True, case["id"]
        ai_count += int(result.requires_ai)
    # Базовый v0.8.4 направлял в ИИ 48 из 70 писем.
    assert ai_count <= 34


def test_vague_historical_context_with_threat_keyword_still_requires_ai():
    result = engine().assess(EmailDocument(
        subject="Новость",
        text="Новостная заметка о расследовании прошлого теракта.",
    ))
    assert result.keywords
    assert result.requires_ai is True
