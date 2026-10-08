from __future__ import annotations

import json
import logging
from pathlib import Path

from app.domain.models import EmailDocument, GatewaySettings, RiskAssessment
from app.infrastructure.risk.analyzers import (
    CharNgramModel,
    benign_context_score,
    keyword_signals,
    phrase_signals,
    strong_benign_context,
    threat_intent_signals,
)
from app.infrastructure.risk.normalizer import normalize

LOGGER = logging.getLogger(__name__)

DEFAULT_TRAINING = [
    {"threat": False, "text": "Привет! Сегодня в 15:00 созвон по проекту."},
    {"threat": False, "text": "Во вложении отчет за неделю, пожалуйста ознакомьтесь."},
    {"threat": False, "text": "Вчера в новостях сообщили о взрыве на заводе. Пострадавших нет."},
    {"threat": False, "text": "Историческая статья о теракте 2004 года."},
    {"threat": False, "text": "Учебный материал о правилах безопасности на производстве."},
    {"threat": False, "text": "Встреча переносится на завтра, новый календарь во вложении."},
    {"threat": False, "text": "Нужно согласовать бюджет и сроки поставки оборудования."},
    {"threat": True, "text": "Завтра в 12:00 произойдет взрыв на промышленном объекте."},
    {"threat": True, "text": "Заминировать здание и устроить теракт."},
    {"threat": True, "text": "Я взломаю систему и украду документы."},
    {"threat": True, "text": "Если не заплатите, я убью сотрудника."},
    {"threat": True, "text": "B3pbIB завтра в 12:00 на объекте."},
    {"threat": True, "text": "в-з-р-ы-в на объекте завтра."},
    {"threat": True, "text": "заминировать здание до конца дня."},
]


class RiskEngine:
    """Conservative local gate.

    The gate may bypass AI only for high-confidence benign context. It must not
    make a final threat verdict locally: anything suspicious or ambiguous goes
    to DeepSeek. The tiny char model is only an obfuscation/generalization signal.
    """

    def __init__(self, settings: GatewaySettings) -> None:
        self.settings = settings
        self.model = self._load_model(settings.risk_training_path)

    def assess(self, email: EmailDocument) -> RiskAssessment:
        source = f"{email.subject}\n{email.text}".strip()
        normalized = normalize(source)
        keywords = keyword_signals(normalized)
        phrases = phrase_signals(normalized)
        intent = threat_intent_signals(normalized)
        benign = benign_context_score(normalized)
        benign_strong = strong_benign_context(normalized, email.subject)

        char_probability = max(
            self.model.predict(normalized.normalized),
            self.model.predict(normalized.obfuscated_variant),
        )
        # Char model participates in the gate only when obfuscation is actually present.
        char_signal = char_probability if normalized.obfuscation_detected else 0.0

        lexical_risk = max(keywords.score, phrases.score, intent.score)
        score = (
            0.62 * lexical_risk
            + 0.28 * char_signal
            + 0.12 * float(normalized.obfuscation_detected)
            - min(0.50, benign)
        )
        score = max(0.0, min(1.0, score))

        has_threat_signal = bool(keywords.matched or phrases.matched or intent.matched)
        has_obfuscation = bool(normalized.obfuscation_detected)
        # High-confidence benign contexts are allowed to bypass threat keywords only
        # when no explicit direct-threat intent is present.
        # A benign context can bypass AI only when there are no threat keywords at all.
        # This deliberately keeps suspicious-but-benign messages with threat vocabulary
        # on the AI path, preserving recall and the conservative cascade contract.
        safe_benign = (
            bool(benign_strong.matched)
            and not keywords.matched
            and not intent.matched
            and not phrases.matched
            and not has_obfuscation
        )

        # Ambiguous content stays on AI. This is the safety boundary we optimize around.
        requires_ai = not safe_benign

        reasons: list[str] = []
        if keywords.matched:
            reasons.append("keyword signals: " + ", ".join(keywords.matched))
        if phrases.matched:
            reasons.append(f"phrase signals: {len(phrases.matched)}")
        if intent.matched:
            reasons.append(f"threat-intent signals: {len(intent.matched)}")
        if normalized.obfuscation_detected:
            reasons.append("possible obfuscation detected")
        if benign:
            reasons.append(f"benign context score={benign:.2f}")
        if benign_strong.matched:
            reasons.append("strong benign context: " + ", ".join(benign_strong.matched[:3]))
        reasons.append(f"char-model threat probability={char_probability:.2f}")
        reasons.append(f"combined risk score={score:.2f}")
        reasons.append("AI required" if requires_ai else "AI bypassed: high-confidence benign context")

        return RiskAssessment(
            score=score,
            requires_ai=requires_ai,
            keywords=list(keywords.matched),
            phrases=list(phrases.matched),
            char_probability=char_probability,
            obfuscation_detected=normalized.obfuscation_detected,
            reason="; ".join(reasons),
        )

    @staticmethod
    def _load_model(path: str) -> CharNgramModel:
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            samples = data.get("samples", [])
            if samples:
                return CharNgramModel(samples)
        except Exception as exc:
            LOGGER.warning("Risk training data unavailable: %s; using built-in seed model", exc)
        return CharNgramModel(DEFAULT_TRAINING)
