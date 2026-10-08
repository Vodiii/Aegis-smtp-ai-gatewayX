from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.domain.models import (
    Action,
    Classification,
    PolicyDecision,
    ProcessingResult,
    RiskAssessment,
    ThreatCategory,
)


class MessageRepository:
    def __init__(self, db_path: str, data_dir: str) -> None:
        self.db_path = db_path
        self.data_dir = Path(data_dir)
        self.raw_dir = self.data_dir / "messages"
        self.raw_dir.mkdir(parents=True, exist_ok=True)
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    processed_at TEXT NOT NULL,
                    message_id TEXT,
                    sender TEXT NOT NULL,
                    recipients_json TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    category TEXT NOT NULL,
                    is_threat INTEGER NOT NULL,
                    confidence REAL NOT NULL,
                    threat_confidence REAL,
                    reason TEXT NOT NULL,
                    evidence_json TEXT NOT NULL,
                    action TEXT NOT NULL,
                    destination TEXT,
                    review INTEGER NOT NULL,
                    processing_time_ms INTEGER NOT NULL,
                    processing_started_at TEXT,
                    processing_finished_at TEXT,
                    raw_path TEXT NOT NULL,
                    forward_status TEXT NOT NULL DEFAULT 'PENDING',
                    forward_error TEXT,
                    classification_source TEXT NOT NULL DEFAULT 'UNKNOWN',
                    decision_reason TEXT NOT NULL DEFAULT '',
                    delivery_key TEXT,
                    risk_score REAL NOT NULL DEFAULT 0.0,
                    risk_requires_ai INTEGER NOT NULL DEFAULT 1,
                    risk_keywords_json TEXT NOT NULL DEFAULT '[]',
                    risk_phrases_json TEXT NOT NULL DEFAULT '[]',
                    risk_char_probability REAL NOT NULL DEFAULT 0.0,
                    risk_obfuscation_detected INTEGER NOT NULL DEFAULT 0,
                    risk_reason TEXT NOT NULL DEFAULT ''
                )
                """
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(messages)").fetchall()}
            migrations = {
                "threat_confidence": "ALTER TABLE messages ADD COLUMN threat_confidence REAL",
                "classification_source": "ALTER TABLE messages ADD COLUMN classification_source TEXT NOT NULL DEFAULT 'UNKNOWN'",
                "decision_reason": "ALTER TABLE messages ADD COLUMN decision_reason TEXT NOT NULL DEFAULT ''",
                "delivery_key": "ALTER TABLE messages ADD COLUMN delivery_key TEXT",
                "risk_score": "ALTER TABLE messages ADD COLUMN risk_score REAL NOT NULL DEFAULT 0.0",
                "risk_requires_ai": "ALTER TABLE messages ADD COLUMN risk_requires_ai INTEGER NOT NULL DEFAULT 1",
                "risk_keywords_json": "ALTER TABLE messages ADD COLUMN risk_keywords_json TEXT NOT NULL DEFAULT '[]'",
                "risk_phrases_json": "ALTER TABLE messages ADD COLUMN risk_phrases_json TEXT NOT NULL DEFAULT '[]'",
                "risk_char_probability": "ALTER TABLE messages ADD COLUMN risk_char_probability REAL NOT NULL DEFAULT 0.0",
                "risk_obfuscation_detected": "ALTER TABLE messages ADD COLUMN risk_obfuscation_detected INTEGER NOT NULL DEFAULT 0",
                "risk_reason": "ALTER TABLE messages ADD COLUMN risk_reason TEXT NOT NULL DEFAULT ''",
                "processing_started_at": "ALTER TABLE messages ADD COLUMN processing_started_at TEXT",
                "processing_finished_at": "ALTER TABLE messages ADD COLUMN processing_finished_at TEXT",
            }
            for column, sql in migrations.items():
                if column not in columns:
                    conn.execute(sql)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_delivery_key ON messages(delivery_key)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_messages_processed_at ON messages(processed_at)")

    @staticmethod
    def make_delivery_key(raw_message: bytes, mail_from: str, recipients: list[str]) -> str:
        digest = hashlib.sha256()
        digest.update(raw_message)
        digest.update(b"\0")
        digest.update(mail_from.strip().lower().encode("utf-8", "ignore"))
        digest.update(b"\0")
        digest.update("\n".join(sorted(item.strip().lower() for item in recipients)).encode("utf-8", "ignore"))
        return digest.hexdigest()

    def find_by_delivery_key(self, delivery_key: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM messages WHERE delivery_key = ? ORDER BY processed_at DESC LIMIT 1",
                (delivery_key,),
            ).fetchone()
        return self._row(row) if row else None

    def save(
        self,
        record_id: str,
        raw_message: bytes,
        email: Any,
        result: ProcessingResult,
        delivery_key: str | None = None,
    ) -> None:
        raw_path = self.raw_dir / f"{record_id}.eml"
        raw_path.write_bytes(raw_message)
        risk = result.risk_assessment
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO messages (
                    id, processed_at, message_id, sender, recipients_json,
                    subject, category, is_threat, confidence, threat_confidence, reason,
                    evidence_json, action, destination, review,
                    processing_time_ms, processing_started_at, processing_finished_at, raw_path, forward_status, forward_error,
                    classification_source, decision_reason, delivery_key,
                    risk_score, risk_requires_ai, risk_keywords_json, risk_phrases_json,
                    risk_char_probability, risk_obfuscation_detected, risk_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record_id,
                    datetime.now(timezone.utc).isoformat(),
                    email.message_id,
                    email.sender,
                    json.dumps(email.recipients, ensure_ascii=False),
                    email.subject,
                    result.classification.category.value,
                    int(result.classification.is_threat),
                    result.classification.confidence,
                    result.classification.threat_confidence,
                    result.classification.reason,
                    json.dumps(result.classification.evidence, ensure_ascii=False),
                    result.decision.action.value,
                    result.decision.destination,
                    int(result.decision.review),
                    result.processing_time_ms,
                    result.processing_started_at.isoformat() if result.processing_started_at else None,
                    result.processing_finished_at.isoformat() if result.processing_finished_at else None,
                    str(raw_path),
                    "PENDING",
                    None,
                    result.classification.source,
                    result.decision.reason,
                    delivery_key,
                    risk.score if risk else 0.0,
                    int(risk.requires_ai) if risk else 1,
                    json.dumps(risk.keywords, ensure_ascii=False) if risk else "[]",
                    json.dumps(risk.phrases, ensure_ascii=False) if risk else "[]",
                    risk.char_probability if risk else 0.0,
                    int(risk.obfuscation_detected) if risk else 0,
                    risk.reason if risk else "",
                ),
            )

    def update_forward_status(self, record_id: str, status: str, error: str | None = None) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE messages SET forward_status = ?, forward_error = ? WHERE id = ?",
                (status, error, record_id),
            )

    def list_messages(self, limit: int = 100) -> list[dict[str, Any]]:
        limit = min(max(limit, 1), 500)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM messages ORDER BY processed_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row(row) for row in rows]

    def get(self, record_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM messages WHERE id = ?", (record_id,)).fetchone()
        return self._row(row) if row else None

    def to_processing_result(self, record_id: str) -> ProcessingResult | None:
        row = self.get(record_id)
        if row is None:
            return None
        classification = Classification(
            category=ThreatCategory(row["category"]),
            is_threat=row["is_threat"],
            confidence=row["confidence"],
            reason=row["reason"],
            evidence=row["evidence"],
            source=row.get("classification_source") or "UNKNOWN",
            threat_confidence=row.get("threat_confidence"),
        )
        decision = PolicyDecision(
            action=Action(row["action"]),
            category=ThreatCategory(row["category"]),
            confidence=row["confidence"],
            destination=row["destination"],
            review=row["review"],
            reason=row.get("decision_reason") or "",
        )
        risk = RiskAssessment(
            score=row.get("risk_score", 0.0),
            requires_ai=bool(row.get("risk_requires_ai", 1)),
            keywords=row.get("risk_keywords", []),
            phrases=row.get("risk_phrases", []),
            char_probability=row.get("risk_char_probability", 0.0),
            obfuscation_detected=bool(row.get("risk_obfuscation_detected", 0)),
            reason=row.get("risk_reason", ""),
        )
        return ProcessingResult(
            classification=classification,
            decision=decision,
            processing_time_ms=row["processing_time_ms"],
            processing_started_at=datetime.fromisoformat(row["processing_started_at"]) if row.get("processing_started_at") else None,
            processing_finished_at=datetime.fromisoformat(row["processing_finished_at"]) if row.get("processing_finished_at") else None,
            risk_assessment=risk,
        )

    def stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS c FROM messages").fetchone()["c"]
            threats = conn.execute("SELECT COUNT(*) AS c FROM messages WHERE is_threat = 1").fetchone()["c"]
            alerted = conn.execute("SELECT COUNT(*) AS c FROM messages WHERE action = 'DELIVER_AND_ALERT'").fetchone()["c"]
            alert_sent = conn.execute("SELECT COUNT(*) AS c FROM messages WHERE forward_status = 'ORIGINAL_AND_ALERT_SENT'").fetchone()["c"]
            ai_called = conn.execute("SELECT COUNT(*) AS c FROM messages WHERE risk_requires_ai = 1").fetchone()["c"]
            fast_bypassed = conn.execute("SELECT COUNT(*) AS c FROM messages WHERE risk_requires_ai = 0").fetchone()["c"]
            by_category = conn.execute("SELECT category, COUNT(*) AS c FROM messages GROUP BY category").fetchall()
            timing = conn.execute(
                "SELECT COALESCE(SUM(processing_time_ms), 0) AS total_ms, "
                "COALESCE(AVG(processing_time_ms), 0) AS avg_ms, "
                "COALESCE(MIN(processing_time_ms), 0) AS min_ms, "
                "COALESCE(MAX(processing_time_ms), 0) AS max_ms FROM messages"
            ).fetchone()
            by_source = conn.execute("SELECT classification_source, COUNT(*) AS c FROM messages GROUP BY classification_source").fetchall()
        return {
            "total": total,
            "threats": threats,
            "alerted": alerted,
            "alert_sent": alert_sent,
            "ai_called": ai_called,
            "fast_bypassed": fast_bypassed,
            "categories": {row["category"]: row["c"] for row in by_category},
            "timing": {
                "total_processing_ms": int(timing["total_ms"]),
                "total_processing_seconds": round(timing["total_ms"] / 1000, 3),
                "avg_processing_ms": round(timing["avg_ms"], 2),
                "min_processing_ms": int(timing["min_ms"]),
                "max_processing_ms": int(timing["max_ms"]),
            },
            "classification_sources": {row["classification_source"]: row["c"] for row in by_source},
        }

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["recipients"] = json.loads(result.pop("recipients_json"))
        result["evidence"] = json.loads(result.pop("evidence_json"))
        result["risk_keywords"] = json.loads(result.pop("risk_keywords_json", "[]"))
        result["risk_phrases"] = json.loads(result.pop("risk_phrases_json", "[]"))
        result["is_threat"] = bool(result["is_threat"])
        result["review"] = bool(result["review"])
        result["risk_requires_ai"] = bool(result["risk_requires_ai"])
        result["risk_obfuscation_detected"] = bool(result["risk_obfuscation_detected"])
        return result
