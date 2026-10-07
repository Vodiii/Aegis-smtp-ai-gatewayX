from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.domain.models import ProcessingResult


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
                    raw_path TEXT NOT NULL,
                    forward_status TEXT NOT NULL DEFAULT 'PENDING',
                    forward_error TEXT
                )
                """
            )
            columns = {row[1] for row in conn.execute("PRAGMA table_info(messages)").fetchall()}
            if "threat_confidence" not in columns:
                conn.execute("ALTER TABLE messages ADD COLUMN threat_confidence REAL")

    def save(self, record_id: str, raw_message: bytes, email: Any, result: ProcessingResult) -> None:
        raw_path = self.raw_dir / f"{record_id}.eml"
        raw_path.write_bytes(raw_message)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO messages (
                    id, processed_at, message_id, sender, recipients_json,
                    subject, category, is_threat, confidence, threat_confidence, reason,
                    evidence_json, action, destination, review,
                    processing_time_ms, raw_path, forward_status, forward_error
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    str(raw_path),
                    "PENDING",
                    None,
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

    def stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS c FROM messages").fetchone()["c"]
            threats = conn.execute("SELECT COUNT(*) AS c FROM messages WHERE is_threat = 1").fetchone()["c"]
            alerted = conn.execute("SELECT COUNT(*) AS c FROM messages WHERE action = 'DELIVER_AND_ALERT'").fetchone()["c"]
            alert_sent = conn.execute("SELECT COUNT(*) AS c FROM messages WHERE forward_status = 'ORIGINAL_AND_ALERT_SENT'").fetchone()["c"]
            by_category = conn.execute(
                "SELECT category, COUNT(*) AS c FROM messages GROUP BY category"
            ).fetchall()
        return {
            "total": total,
            "threats": threats,
            "alerted": alerted,
            "alert_sent": alert_sent,
            "categories": {row["category"]: row["c"] for row in by_category},
        }

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["recipients"] = json.loads(result.pop("recipients_json"))
        result["evidence"] = json.loads(result.pop("evidence_json"))
        result["is_threat"] = bool(result["is_threat"])
        result["review"] = bool(result["review"])
        return result
