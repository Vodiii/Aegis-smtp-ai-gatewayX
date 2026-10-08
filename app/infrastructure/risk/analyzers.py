from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import math
import re

from app.infrastructure.risk.normalizer import NormalizedText

CATEGORY_KEYWORDS = {
    "TERRORISM": (
        "теракт", "террорист", "заложник", "бомба", "заминирован",
        "диверсия", "массовое нападение", "массовые жертвы", "атака на наши цели",
    ),
    "TECHNOGENIC": (
        "авария", "взрыв", "утечка", "выброс", "опасного вещества", "радиация",
        "пожар", "обрушение", "утечка газа", "утечка химикатов",
        "промышленный объект", "опасное производство", "техногенн", "энергосеть",
        "гэс", "аэс", "химзавод", "водозабор",
    ),
    "ILLEGAL": (
        "взлом", "ограб", "похит", "краж", "подожг", "проникнуть", "украсть",
        "незаконно", "вредоносн", "покалеч", "шантаж", "заплатишь", "заплатите",
    ),
    "OTHER_THREAT": (
        "убью", "убить", "причиню вред", "причинить вред", "нанесу вред", "нанести вред", "расправ",
        "угрожаю", "угроза", "уничтожу репутацию", "биологическое оружие", "выложу данные", "отравим реку",
    ),
}

THREAT_PHRASES = (
    r"\bзавтра\b.{0,80}\b(взрыв|теракт|подрыв|авария|нападение|взорву|подорву|убью|украду)\b",
    r"\b(будет|произойдет|произойд[её]т|ожидается|возможен|возможна|возможное)\b.{0,100}\b(взрыв|авария|нападение|утечка|теракт)\b",
    r"\b(заминировать|взорвать|подорвать|поджечь|взломать|украсть|похитить)\b",
    r"\b(если|иначе).{0,80}\b(убью|убить|причиню вред|нанесу вред|взорву|подожгу|покалечу)\b",
    r"\b(угрожаю|угроза).{0,80}\b(убийством|взрывом|нападением|поджогом)\b",
)

# Direct threat-intent patterns are used ONLY as an AI gate signal. They do not
# classify the category and never by themselves produce a final benign verdict.
THREAT_INTENT_PATTERNS = (
    r"\bтебя\s+(достанем|достанут|найду|найд[её]м)\b",
    r"\bпожалеешь\b",
    r"\b(последн(ей|яя)|последним)\s+(в твоей жизни|дн[её]м)\b",
    r"\b(готовим|планируем|планирую|подготовлена|подготовили|собираемся|будем|намерены)\b.{0,80}\b(атак|напад|уби|взор|подожг|похит|вред|уничтож|проник)\w*\b",
    r"\b(we\s+will|i\s+will|we're\s+going\s+to|i'm\s+going\s+to)\b.{0,80}\b(hurt|kill|burn|kidnap|attack|bomb|detonate|hack|release)\b",
    r"\b(you\s+will\s+regret|this\s+will\s+be\s+the\s+last)\b",
)

# Strongly benign contexts. A FAST verdict is allowed only when these contexts
# are present and no direct threat-intent / obfuscation / threat phrase exists.
BENIGN_STRONG_PATTERNS = (
    r"\bвчера\b.{0,80}\b(произошел|произошла|произошли)\b",
    r"\b(авария|угроза)\s+уже\s+(устранена|миновала|закончилась)\b",
    r"\b(убийство)\s+раскрыто\b",
    r"\bпредотвратили\b.{0,80}\bтеракт\b",
    r"\bведутся\s+восстановительные\s+работы\b",
    r"\bполиция\s+расследует\b",
    r"\bобзор\s+недели\b",
    r"\bдайджест\b",
    r"\b(угроза|катастроф[аы])\s+миновала\b",
    r"\b(цитата|процитировали|в\s+книге|в\s+фильме|в\s+романе)\b",
    r"\bв\s+шахматах\b",
    r"\bпересылаю\s+тебе\b.{0,100}\bписьмо\s+с\s+угрозой\b",
    r"\bв\s+договоре\b",
    r"\bна\s+выборах\b",
    r"\bэто\s+цитата,?\s+а\s+не\s+призыв\b",
    r"\bкак\s+террорист\s+с\s+дедлайнами\b",
    r"\bубью\s+время\b",
    r"\bвзорвал\s+чат\b",
    r"\bзадача\s*[—-]\s*(настоящий\s+)?убийца\b",
    r"\bуничтожу\s+этот\s+экзамен\b",
    r"\bбез\s+угроз\b",
    r"\bнет\s+(угроз|намерения|призывов)\b",
    r"\bопасности\s+нет\b",
    r"\bучебн",
    r"\bинформационн(ый|ая|ое)\s+материал\b",
    r"\b(историческ|архивн|прошл)\w*\b",
    r"\b(последств|предотвращени|рекомендаци)\w*\b.{0,80}\b(авари|угроз|теракт|инцидент|утечк)\w*\b",
    r"\bгипотетическ\w*\s+угроз\w*\b",
    r"\bпосле\s+тренировк\w*\b",
    r"\bсудебн\w*\s+новост\w*\b",
)

BUSINESS_SUBJECT_PATTERNS = (
    r"\bвстреч",
    r"\bотпуск\b",
    r"\bсч[её]т\b",
    r"\bотч[её]т\b",
    r"\bсозвон\b",
    r"\bдокумент",
    r"\bправк",
    r"\bакт\b",
    r"\bпоздрав",
    r"\bсуббот",
    r"\bповестк",
    r"\bбюджет\b",
    r"\bстатус\s+проекта\b",
    r"\bпоставк\w*\b",
    r"\bкалендар\w*\b",
    r"\bзаявк\w*\b",
    r"\bдоставк\w*\b",
    r"\bкомандировк\w*\b",
    r"\bобновлени\w*\b",
    r"\bсрок\w*\b",
    r"\bреквизит\w*\b",
    r"\bподпис\w*\b",
    r"\bобед\w*\b",
    r"\bдоступ\w*\b",
    r"\bзадач\w*\b",
    r"\bплан\w*\b",
)

@dataclass(frozen=True)
class SignalResult:
    matched: tuple[str, ...]
    score: float


def _matches(patterns: tuple[str, ...], text: str, limit: int = 8) -> list[str]:
    matched: list[str] = []
    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            matched.append(pattern)
    return matched[:limit]


def keyword_signals(text: NormalizedText) -> SignalResult:
    compact_variant = re.sub(r"[^\w\u0400-\u04ff]+", "", text.obfuscated_variant, flags=re.UNICODE)
    haystacks = (text.normalized, text.obfuscated_variant, text.compact, compact_variant)
    matched: list[str] = []
    for terms in CATEGORY_KEYWORDS.values():
        for term in terms:
            compact_term = re.sub(r"[^\w\u0400-\u04ff]+", "", term, flags=re.UNICODE)
            if any(term in haystack for haystack in haystacks) or any(compact_term in haystack for haystack in (text.compact, compact_variant)):
                matched.append(term)
    unique = list(dict.fromkeys(matched))
    if not unique:
        return SignalResult(tuple(), 0.0)
    score = min(0.62, 0.16 + 0.08 * len(unique))
    return SignalResult(tuple(unique[:8]), score)


def phrase_signals(text: NormalizedText) -> SignalResult:
    matched = _matches(THREAT_PHRASES, text.normalized, 5)
    if not matched:
        matched = _matches(THREAT_PHRASES, text.obfuscated_variant, 5)
    if not matched:
        return SignalResult(tuple(), 0.0)
    return SignalResult(tuple(matched), min(0.82, 0.42 + 0.12 * len(matched)))


def threat_intent_signals(text: NormalizedText) -> SignalResult:
    matched = _matches(THREAT_INTENT_PATTERNS, text.normalized, 6)
    if not matched:
        matched = _matches(THREAT_INTENT_PATTERNS, text.obfuscated_variant, 6)
    if not matched:
        return SignalResult(tuple(), 0.0)
    return SignalResult(tuple(matched), min(0.90, 0.55 + 0.10 * len(matched)))


def strong_benign_context(text: NormalizedText, subject: str = "") -> SignalResult:
    matches = _matches(BENIGN_STRONG_PATTERNS, text.normalized, 8)
    if not matches and subject:
        subject_norm = subject.casefold().strip()
        if _matches(BUSINESS_SUBJECT_PATTERNS, subject_norm, 2):
            matches = ["business subject"]
    if not matches and not text.normalized and not text.original.strip():
        matches = ["empty message body"]
    if not matches:
        return SignalResult(tuple(), 0.0)
    return SignalResult(tuple(matches), min(0.88, 0.55 + 0.08 * len(matches)))


def benign_context_score(text: NormalizedText) -> float:
    # Preserve the old public score semantics for compatibility.
    hits = sum(1 for pattern in BENIGN_STRONG_PATTERNS if re.search(pattern, text.normalized, re.IGNORECASE))
    return min(0.75, 0.22 * hits)


class CharNgramModel:
    """Tiny character-trigram Naive Bayes model trained from a local JSON dataset."""

    def __init__(self, samples: list[dict]) -> None:
        self.alpha = 1.0
        self.class_counts = Counter()
        self.ngram_counts = {"threat": Counter(), "benign": Counter()}
        self.total_ngrams = Counter()
        for sample in samples:
            label = "threat" if bool(sample.get("threat")) else "benign"
            text = str(sample.get("text", "")).casefold()
            self.class_counts[label] += 1
            grams = self._grams(text)
            self.ngram_counts[label].update(grams)
            self.total_ngrams[label] += len(grams)
        self.vocab = set(self.ngram_counts["threat"]) | set(self.ngram_counts["benign"])

    @staticmethod
    def _grams(text: str) -> list[str]:
        padded = f"  {text}  "
        return [padded[i:i + 3] for i in range(max(0, len(padded) - 2))]

    def predict(self, text: str) -> float:
        total_classes = sum(self.class_counts.values())
        if not self.vocab or not total_classes:
            return 0.5

        grams = self._grams(text.casefold())
        priors = {
            c: (self.class_counts[c] + 1) / (total_classes + 2)
            for c in ("threat", "benign")
        }
        logp = {c: math.log(priors[c]) for c in priors}
        vocab_size = len(self.vocab)

        for cls in logp:
            denominator = self.total_ngrams[cls] + self.alpha * vocab_size
            for gram in grams:
                logp[cls] += math.log((self.ngram_counts[cls][gram] + self.alpha) / denominator)

        max_log = max(logp.values())
        exp_values = {c: math.exp(logp[c] - max_log) for c in logp}
        return exp_values["threat"] / (exp_values["threat"] + exp_values["benign"])
