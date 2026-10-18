"""Регрессионные случаи для пересечений категорий из внешнего QA-набора."""

import pytest

from app.application.category_policy import apply_category_policy
from app.domain.models import EmailDocument, ThreatCategory


@pytest.mark.parametrize(
    ("case_id", "subject", "body", "initial", "expected"),
    [
        ("terrorism_01", "Предупреждение", "Завтра в 12:00 в торговом центре произойдёт взрыв, если наши требования не будут выполнены.", "TECHNOGENIC", "TERRORISM"),
        ("terrorism_04", "Призыв", "Призываем к насилию: все объекты будут уничтожены, если требования не будут выполнены.", "OTHER_THREAT", "TERRORISM"),
        ("terrorism_05", "Скоро", "Скоро всё сгорит. Готовьтесь к большой огненной атаке на наши цели.", "OTHER_THREAT", "TERRORISM"),
        ("terrorism_06", "Внимание", "Мы в3рвём ТЦ завтра в 12:00, если не выплатят деньги.", "OTHER_THREAT", "TERRORISM"),
        ("terrorism_07", "Threat", "There is a bomb in the subway. Pay 1 million or we detonate it.", "OTHER_THREAT", "TERRORISM"),
        ("technogenic_02", "Отключение", "Мы отключим энергосеть города в ближайшие дни. Готовьтесь к темноте.", "OTHER_THREAT", "TECHNOGENIC"),
        ("illegal_05", "Угроза", "Найду тебя и убью. Это не шутка.", "OTHER_THREAT", "ILLEGAL"),
        ("illegal_06", "Сосед", "Заплатишь мне за молчание, иначе сосед узнает всё.", "OTHER_THREAT", "ILLEGAL"),
        ("illegal_07", "Warning", "We will hurt your family if you don't pay.", "OTHER_THREAT", "ILLEGAL"),
        ("illegal_08", "Журналист", "Если опубликуешь эту статью, она станет последней в твоей жизни.", "OTHER_THREAT", "ILLEGAL"),
        ("other_05", "Клиенты", "Мы взломаем систему и выложим данные клиентов в открытый доступ.", "ILLEGAL", "OTHER_THREAT"),
    ],
)
def test_external_qa_category_regressions(case_id, subject, body, initial, expected):
    email = EmailDocument(subject=subject, text=body)
    category, _reason = apply_category_policy(email, ThreatCategory(initial))
    assert category.value == expected, case_id
