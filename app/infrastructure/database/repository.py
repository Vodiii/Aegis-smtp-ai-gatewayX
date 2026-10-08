from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from email import policy
from email.parser import BytesParser
from datetime import datetime, timezone
import uuid
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
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS queue_jobs (
                    job_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    delivery_key TEXT NOT NULL UNIQUE,
                    sender TEXT NOT NULL,
                    recipients_json TEXT NOT NULL,
                    raw_path TEXT NOT NULL,
                    state TEXT NOT NULL DEFAULT 'QUEUED',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    available_at REAL NOT NULL,
                    locked_at REAL,
                    last_error TEXT
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_queue_jobs_due ON queue_jobs(state, available_at)")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS deliveries (
                    delivery_id TEXT PRIMARY KEY,
                    message_id TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    raw_message BLOB NOT NULL,
                    status TEXT NOT NULL DEFAULT 'PENDING',
                    attempts INTEGER NOT NULL DEFAULT 0,
                    next_attempt_at REAL NOT NULL,
                    last_error TEXT,
                    sent_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(message_id, kind, recipient)
                )
                """
            )
            conn.execute("CREATE INDEX IF NOT EXISTS idx_deliveries_due ON deliveries(status, next_attempt_at)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_deliveries_message ON deliveries(message_id)")

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

    def enqueue_message(self, raw_message: bytes, mail_from: str, recipients: list[str], delivery_key: str) -> tuple[str, bool]:
        if not recipients:
            raise ValueError("No recipients")
        existing = self.find_queue_by_delivery_key(delivery_key)
        if existing:
            return existing["job_id"], False
        spool_dir = self.data_dir / "queue"
        spool_dir.mkdir(parents=True, exist_ok=True)
        job_id = str(uuid.uuid4())
        raw_path = spool_dir / f"{job_id}.eml"
        temp_path = spool_dir / f".{job_id}.tmp"
        with temp_path.open("wb") as fh:
            fh.write(raw_message)
            fh.flush()
            import os
            os.fsync(fh.fileno())
        temp_path.replace(raw_path)
        now_iso = datetime.now(timezone.utc).isoformat()
        now = time.time()
        try:
            with self._connect() as conn:
                conn.execute(
                    """INSERT INTO queue_jobs(
                        job_id, created_at, updated_at, delivery_key, sender,
                        recipients_json, raw_path, state, attempts, available_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'QUEUED', 0, ?)""",
                    (
                        job_id,
                        now_iso,
                        now_iso,
                        delivery_key,
                        mail_from,
                        json.dumps(recipients, ensure_ascii=False),
                        str(raw_path),
                        now,
                    ),
                )
        except sqlite3.IntegrityError:
            try:
                raw_path.unlink(missing_ok=True)
            except Exception:
                pass
            existing = self.find_queue_by_delivery_key(delivery_key)
            if existing:
                return existing["job_id"], False
            raise
        return job_id, True

    def find_queue_by_delivery_key(self, delivery_key: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM queue_jobs WHERE delivery_key = ?", (delivery_key,)).fetchone()
        return self._queue_row(row) if row else None

    def claim_next_job(self) -> dict[str, Any] | None:
        now = time.time()
        with self._connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM queue_jobs WHERE state IN ('QUEUED','RETRY') AND available_at <= ? ORDER BY created_at LIMIT 1",
                (now,),
            ).fetchone()
            if not row:
                conn.commit()
                return None
            job_id = row["job_id"]
            attempts = int(row["attempts"]) + 1
            conn.execute(
                "UPDATE queue_jobs SET state='PROCESSING', attempts=?, locked_at=?, updated_at=? WHERE job_id=?",
                (attempts, now, datetime.now(timezone.utc).isoformat(), job_id),
            )
            conn.commit()
            result = dict(row)
            result["attempts"] = attempts
            result["recipients"] = json.loads(result.pop("recipients_json"))
            return result

    def recover_stale_jobs(self, stale_seconds: float) -> int:
        cutoff = time.time() - stale_seconds
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE queue_jobs SET state='RETRY', available_at=?, locked_at=NULL, updated_at=?, last_error=? "
                "WHERE state='PROCESSING' AND locked_at IS NOT NULL AND locked_at < ?",
                (time.time(), now_iso, "Recovered stale processing job after restart", cutoff),
            )
            return cursor.rowcount

    def retry_job(self, job_id: str, delay_seconds: float, error: str) -> None:
        now = time.time()
        with self._connect() as conn:
            conn.execute(
                "UPDATE queue_jobs SET state='RETRY', available_at=?, locked_at=NULL, updated_at=?, last_error=? WHERE job_id=?",
                (now + max(0.0, delay_seconds), datetime.now(timezone.utc).isoformat(), error[:4000], job_id),
            )

    def mark_job_done(self, job_id: str) -> None:
        self._set_job_state(job_id, "DONE", None)
        self._cleanup_queue_spool(job_id)

    def dead_letter_job(self, job_id: str, error: str) -> None:
        self._set_job_state(job_id, "DEAD_LETTER", error)

    def _set_job_state(self, job_id: str, state: str, error: str | None) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE queue_jobs SET state=?, updated_at=?, locked_at=NULL, last_error=? WHERE job_id=?",
                (state, datetime.now(timezone.utc).isoformat(), error[:4000] if error else None, job_id),
            )

    def _cleanup_queue_spool(self, job_id: str) -> None:
        with self._connect() as conn:
            row = conn.execute("SELECT raw_path FROM queue_jobs WHERE job_id=?", (job_id,)).fetchone()
        if row:
            try:
                Path(row["raw_path"]).unlink(missing_ok=True)
            except Exception:
                pass

    @staticmethod
    def read_spooled_message(raw_path: str) -> bytes:
        return Path(raw_path).read_bytes()

    def ensure_delivery_records(self, message_id: str, original_recipients: list[str], alert_destination: str | None) -> None:
        message = self.get(message_id)
        if not message:
            raise KeyError(message_id)
        raw = Path(message["raw_path"]).read_bytes()
        original_host = self._delivery_host("ORIGINAL")
        original_port = self._delivery_port("ORIGINAL")
        now_iso = datetime.now(timezone.utc).isoformat()
        now = time.time()
        with self._connect() as conn:
            original_seed_status = "SENT" if message.get("forward_status") in {
                "ORIGINAL_SENT", "ORIGINAL_AND_ALERT_SENT", "ORIGINAL_SENT_ALERT_FAILED", "ORIGINAL_SENT_ALERT_PENDING"
            } else "PENDING"
            for recipient in original_recipients:
                conn.execute(
                    """INSERT OR IGNORE INTO deliveries(
                        delivery_id, message_id, kind, recipient, host, port, raw_message,
                        status, attempts, next_attempt_at, created_at, updated_at, sent_at
                    ) VALUES (?, ?, 'ORIGINAL', ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)""",
                    (str(uuid.uuid4()), message_id, recipient, original_host, original_port, raw, original_seed_status, now, now_iso, now_iso, now_iso if original_seed_status == "SENT" else None),
                )
            if alert_destination:
                alert_seed_status = "SENT" if message.get("forward_status") == "ORIGINAL_AND_ALERT_SENT" else "PENDING"
                alert_host = self._delivery_host("ALERT")
                alert_port = self._delivery_port("ALERT")
                alert_raw = self._build_alert_copy(raw, alert_destination)
                conn.execute(
                    """INSERT OR IGNORE INTO deliveries(
                        delivery_id, message_id, kind, recipient, host, port, raw_message,
                        status, attempts, next_attempt_at, created_at, updated_at, sent_at
                    ) VALUES (?, ?, 'ALERT', ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)""",
                    (str(uuid.uuid4()), message_id, alert_destination, alert_host, alert_port, alert_raw, alert_seed_status, now, now_iso, now_iso, now_iso if alert_seed_status == "SENT" else None),
                )

    def ensure_delivery_records_from_message(self, message_id: str) -> None:
        message = self.get(message_id)
        if not message:
            raise KeyError(message_id)
        alert = message["destination"] if message["action"] == "DELIVER_AND_ALERT" else None
        # The settings-bound hosts are injected through init below.
        self.ensure_delivery_records(message_id, message["recipients"], alert)

    def configure_delivery_endpoints(self, settings: Any) -> None:
        self._original_smtp_host = settings.original_smtp_host
        self._original_smtp_port = settings.original_smtp_port
        self._alert_smtp_host = settings.alert_smtp_host
        self._alert_smtp_port = settings.alert_smtp_port
        self._loop_token = settings.gateway_loop_token

    def _delivery_host(self, kind: str) -> str:
        return getattr(self, "_original_smtp_host" if kind == "ORIGINAL" else "_alert_smtp_host", "localhost")

    def _delivery_port(self, kind: str) -> int:
        return int(getattr(self, "_original_smtp_port" if kind == "ORIGINAL" else "_alert_smtp_port", 25))

    def _build_alert_copy(self, raw: bytes, destination: str) -> bytes:
        message = BytesParser(policy=policy.default).parsebytes(raw)
        token = getattr(self, "_loop_token", "")
        message["X-AI-SMTP-Gateway-Alert"] = "1"
        if token:
            message["X-AI-SMTP-Gateway-Token"] = token
        message["X-AI-SMTP-Gateway-Alert-Recipient"] = destination
        return message.as_bytes(policy=policy.SMTP)

    def due_deliveries(self, message_id: str) -> list[dict[str, Any]]:
        now = time.time()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM deliveries WHERE message_id=? AND status IN ('PENDING','RETRY') AND next_attempt_at <= ? ORDER BY kind, recipient",
                (message_id, now),
            ).fetchall()
        result = []
        for row in rows:
            item = dict(row)
            item["raw_message"] = bytes(item["raw_message"])
            result.append(item)
        return result

    def mark_delivery_sent(self, delivery_id: str) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "UPDATE deliveries SET status='SENT', sent_at=?, updated_at=?, last_error=NULL, attempts=attempts+1 WHERE delivery_id=?",
                (now_iso, now_iso, delivery_id),
            )

    def mark_delivery_retry(self, delivery_id: str, delay_seconds: float, error: str) -> None:
        now = time.time()
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "UPDATE deliveries SET status='RETRY', next_attempt_at=?, updated_at=?, last_error=?, attempts=attempts+1 WHERE delivery_id=?",
                (now + delay_seconds, now_iso, error[:4000], delivery_id),
            )

    def mark_delivery_final_failure(self, delivery_id: str, error: str) -> None:
        now_iso = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "UPDATE deliveries SET status='FAILED_FINAL', updated_at=?, last_error=?, attempts=attempts+1 WHERE delivery_id=?",
                (now_iso, error[:4000], delivery_id),
            )

    def delivery_summary(self, message_id: str) -> dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) AS c FROM deliveries WHERE message_id=? GROUP BY status", (message_id,)
            ).fetchall()
        counts = {row["status"]: int(row["c"]) for row in rows}
        return {
            "sent": counts.get("SENT", 0),
            "pending": counts.get("PENDING", 0),
            "retryable": counts.get("RETRY", 0),
            "final_failed": counts.get("FAILED_FINAL", 0),
        }

    def next_delivery_delays(self, message_id: str) -> list[float]:
        now = time.time()
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT next_attempt_at FROM deliveries WHERE message_id=? AND status='RETRY' ORDER BY next_attempt_at",
                (message_id,),
            ).fetchall()
        return [max(0.0, float(row["next_attempt_at"]) - now) for row in rows]

    def delivery_error_summary(self, message_id: str) -> str:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT kind, recipient, status, last_error FROM deliveries WHERE message_id=? AND status!='SENT'",
                (message_id,),
            ).fetchall()
        parts = [f"{r['kind']} {r['recipient']}: {r['status']} {r['last_error'] or ''}" for r in rows]
        return "; ".join(parts)[:4000] or "Pending deliveries"

    def refresh_forward_status(self, message_id: str) -> None:
        summary = self.delivery_summary(message_id)
        with self._connect() as conn:
            alert_total = conn.execute("SELECT COUNT(*) AS c FROM deliveries WHERE message_id=? AND kind='ALERT'", (message_id,)).fetchone()["c"]
            original_failed = conn.execute("SELECT COUNT(*) AS c FROM deliveries WHERE message_id=? AND kind='ORIGINAL' AND status='FAILED_FINAL'", (message_id,)).fetchone()["c"]
            alert_failed = conn.execute("SELECT COUNT(*) AS c FROM deliveries WHERE message_id=? AND kind='ALERT' AND status='FAILED_FINAL'", (message_id,)).fetchone()["c"]
            alert_retry = conn.execute("SELECT COUNT(*) AS c FROM deliveries WHERE message_id=? AND kind='ALERT' AND status IN ('PENDING','RETRY')", (message_id,)).fetchone()["c"]
            original_pending = conn.execute("SELECT COUNT(*) AS c FROM deliveries WHERE message_id=? AND kind='ORIGINAL' AND status IN ('PENDING','RETRY')", (message_id,)).fetchone()["c"]
            if original_failed:
                status = "ORIGINAL_FAILED"
            elif original_pending:
                status = "ORIGINAL_PENDING"
            elif alert_total and alert_failed:
                status = "ORIGINAL_SENT_ALERT_FAILED"
            elif alert_total and alert_retry:
                status = "ORIGINAL_SENT_ALERT_PENDING"
            elif alert_total:
                status = "ORIGINAL_AND_ALERT_SENT"
            else:
                status = "ORIGINAL_SENT"
            conn.execute("UPDATE messages SET forward_status=?, forward_error=? WHERE id=?", (status, self.delivery_error_summary(message_id) or None, message_id))

    def queue_stats(self) -> dict[str, int]:
        with self._connect() as conn:
            rows = conn.execute("SELECT state, COUNT(*) AS c FROM queue_jobs GROUP BY state").fetchall()
        return {row["state"]: int(row["c"]) for row in rows}

    @staticmethod
    def _queue_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["recipients"] = json.loads(result.pop("recipients_json"))
        return result

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
