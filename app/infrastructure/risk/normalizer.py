from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass


CONFUSABLES = str.maketrans({
    "A": "А", "a": "а", "B": "В", "b": "в", "C": "С", "c": "с",
    "E": "Е", "e": "е", "H": "Н", "K": "К", "k": "к", "M": "М",
    "m": "м", "O": "О", "o": "о", "P": "Р", "p": "р", "T": "Т",
    "X": "Х", "x": "х", "Y": "У", "y": "у", "3": "з", "0": "о",
    "6": "б", "8": "в", "9": "д", "1": "и", "!": "и",
})

LEET = str.maketrans({
    "0": "о", "1": "и", "3": "з", "4": "ч", "5": "с", "6": "б",
    "7": "т", "8": "в", "9": "д", "@": "а", "$": "с",
})


@dataclass(frozen=True)
class NormalizedText:
    original: str
    normalized: str
    compact: str
    obfuscated_variant: str
    obfuscation_detected: bool


def normalize(text: str) -> NormalizedText:
    original = text or ""
    value = unicodedata.normalize("NFKC", original).replace("\u00a0", " ")
    value = value.casefold()
    normalized = re.sub(r"\s+", " ", value).strip()
    compact = re.sub(r"[^\w\u0400-\u04ff]+", "", normalized, flags=re.UNICODE)

    # Дополнительный вариант текста для обнаружения. Он никогда не заменяет оригинал.
    variant = normalized.translate(CONFUSABLES).translate(LEET)
    variant = re.sub(r"[\W_]+", " ", variant, flags=re.UNICODE)
    variant = re.sub(r"\s+", " ", variant).strip()

    tokens = re.findall(r"[A-Za-zА-Яа-яЁё0-9#@_$\-]+", original)
    # Смешение алфавитов считается подозрительным только при соприкосновении латинских
    # и кириллических букв. Обычные слова через дефис, например «HTML-письмо», — не обфускация.
    mixed_token = any(
        bool(re.search(r"[A-Za-zА-Яа-яЁё][A-Za-zА-Яа-яЁё]", token))
        and bool(re.search(r"[A-Za-zА-Яа-яЁё]", token))
        and bool(re.search(r"[A-Za-z]", token))
        and bool(re.search(r"[А-Яа-яЁё]", token))
        for token in re.split(r"[\s,;:()\[\]{}<>/\\_\-]+", original)
    )

    # Подозрительную замену букв цифрами ищем только ВНУТРИ слова.
    # Обычные рабочие идентификаторы вроде PRJ-1000 или Invoice2026 не должны считаться
    # обфускацией лишь потому, что содержат цифры.
    leet_token = False
    for token in tokens:
        compact_token = re.sub(r"[-_]+", "", token)
        if not bool(re.search(r"[A-Za-zА-Яа-яЁё]", compact_token)):
            continue
        if not bool(re.search(r"[0-9#@_$]", compact_token)):
            continue
        positions = [i for i, char in enumerate(compact_token) if char in "0123456789#@$" ]
        if any(
            0 < pos < len(compact_token) - 1
            and bool(re.match(r"[A-Za-zА-Яа-яЁё]", compact_token[pos - 1]))
            and bool(re.match(r"[A-Za-zА-Яа-яЁё]", compact_token[pos + 1]))
            for pos in positions
        ):
            leet_token = True
            break

    repeated_separators = bool(re.search(r"[\-_.#*@]{2,}", original))
    obfuscated = mixed_token or leet_token or repeated_separators

    return NormalizedText(
        original=original,
        normalized=normalized,
        compact=compact,
        obfuscated_variant=variant,
        obfuscation_detected=obfuscated,
    )
