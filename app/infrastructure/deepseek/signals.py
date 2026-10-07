from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ThreatSignal:
    category: str
    phrases: tuple[str, ...]


# Only high-signal phrases are used here. These are NOT a replacement for AI;
# they are used to detect contradictions such as "strong threat wording + BENIGN".
TERRORISM_SIGNALS: tuple[str, ...] = (
    "угроза взрыва",
    "захват заложников",
    "массового нападения",
    "террористическ",
    "теракт",
)

TECHNOGENIC_SIGNALS: tuple[str, ...] = (
    "техногенная авария",
    "техногенной аварии",
    "техногенной аварией",
    "авария на промышленном объекте",
    "авария на промышленном предприятии",
    "авария на заводе",
    "выброс опасного вещества",
    "утечка газа",
    "утечка химикатов",
    "радиационная авария",
)


def detect_high_signal_conflicts(subject: str, body: str) -> tuple[ThreatSignal, ...]:
    text = f"{subject}\n{body}".casefold()
    signals: list[ThreatSignal] = []

    terrorism_hits = tuple(phrase for phrase in TERRORISM_SIGNALS if phrase in text)
    if len(terrorism_hits) >= 2 or any(
        phrase in text for phrase in ("террористическ", "теракт")
    ):
        signals.append(ThreatSignal("TERRORISM", terrorism_hits))

    technogenic_hits = tuple(phrase for phrase in TECHNOGENIC_SIGNALS if phrase in text)
    if len(technogenic_hits) >= 1:
        signals.append(ThreatSignal("TECHNOGENIC", technogenic_hits))

    return tuple(signals)
