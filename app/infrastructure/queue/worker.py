from __future__ import annotations

import logging
import smtplib
import threading
import time
import uuid
from email import policy
from email.parser import BytesParser
from typing import Any

from app.application.processing_service import EmailProcessor
from app.domain.models import Action, GatewaySettings
from app.infrastructure.database.repository import MessageRepository

LOGGER = logging.getLogger("app.queue")


class DeliveryWorker:
    """Durable background worker for classification and downstream delivery.

    The SMTP transaction only persists the message into SQLite + raw spool and
    returns 250. The worker then performs classification and delivery with
    per-recipient durable state. This gives the gateway at-least-once delivery
    semantics with crash recovery; SMTP itself cannot provide exactly-once
    delivery across a process crash between downstream acceptance and state
    persistence.
    """

    def __init__(self, repository: MessageRepository, processor: EmailProcessor, settings: GatewaySettings) -> None:
        self.repository = repository
        self.processor = processor
        self.settings = settings
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self.loop_token = settings.gateway_loop_token

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self.repository.recover_stale_jobs(self.settings.queue_stale_seconds)
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="delivery-worker", daemon=True)
        self._thread.start()
        LOGGER.info("Delivery worker started")

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=max(2.0, self.settings.queue_poll_interval_seconds * 4))
        LOGGER.info("Delivery worker stopped")

    def _run(self) -> None:
        while not self._stop_event.is_set():
            job = self.repository.claim_next_job()
            if not job:
                self._stop_event.wait(self.settings.queue_poll_interval_seconds)
                continue
            try:
                self._process_job(job)
            except Exception:
                LOGGER.exception("Unhandled queue job failure job_id=%s", job["job_id"])
                if int(job["attempts"]) >= self.settings.queue_max_attempts:
                    self.repository.dead_letter_job(job["job_id"], "Maximum queue processing attempts exceeded")
                else:
                    self.repository.retry_job(
                        job["job_id"],
                        self._backoff_seconds(job["attempts"]),
                        "Unhandled worker exception",
                    )

    def _process_job(self, job: dict[str, Any]) -> None:
        raw = self.repository.read_spooled_message(job["raw_path"])
        existing = self.repository.find_by_delivery_key(job["delivery_key"])

        if existing:
            message_id = existing["id"]
            result = self.repository.to_processing_result(message_id)
            if result is None:
                raise RuntimeError(f"Processed message {message_id} cannot be reconstructed")
            LOGGER.info("Resuming durable job=%s from message=%s", job["job_id"], message_id)
        else:
            message_id, email, result = self.processor.process(raw, delivery_key=job["delivery_key"])
            self.repository.ensure_delivery_records(
                message_id,
                email.recipients,
                result.decision.action == Action.DELIVER_AND_ALERT and self.settings.mode != "AUDIT"
                and result.decision.destination or None,
            )

        self.repository.ensure_delivery_records_from_message(message_id)
        self._deliver_due(message_id, job)

        summary = self.repository.delivery_summary(message_id)
        if summary["pending"] == 0 and summary["retryable"] == 0:
            if summary["final_failed"] == 0:
                self.repository.mark_job_done(job["job_id"])
            else:
                self.repository.dead_letter_job(job["job_id"], "One or more deliveries failed permanently")
        else:
            delay = self._next_delay_for_message(message_id)
            self.repository.retry_job(job["job_id"], delay, self.repository.delivery_error_summary(message_id))

    def _deliver_due(self, message_id: str, job: dict[str, Any]) -> None:
        deliveries = self.repository.due_deliveries(message_id)
        if not deliveries:
            return
        for delivery in deliveries:
            if self._stop_event.is_set():
                return
            try:
                if self._is_loop_copy(delivery["raw_message"]):
                    self.repository.mark_delivery_final_failure(
                        delivery["delivery_id"], "Gateway alert loop marker detected"
                    )
                    continue
                self._send_one(
                    job["sender"],
                    delivery["recipient"],
                    delivery["raw_message"],
                    delivery["host"],
                    delivery["port"],
                )
                self.repository.mark_delivery_sent(delivery["delivery_id"])
            except Exception as exc:
                retryable = self._is_retryable_smtp_error(exc)
                if retryable:
                    next_attempt = int(delivery["attempts"]) + 1
                    if next_attempt >= self.settings.delivery_max_attempts:
                        self.repository.mark_delivery_final_failure(delivery["delivery_id"], str(exc))
                    else:
                        self.repository.mark_delivery_retry(
                            delivery["delivery_id"],
                            self._backoff_seconds(next_attempt, base=self.settings.delivery_retry_base_seconds),
                            str(exc),
                        )
                else:
                    self.repository.mark_delivery_final_failure(delivery["delivery_id"], str(exc))
                LOGGER.exception(
                    "Delivery failed message=%s delivery=%s recipient=%s retryable=%s",
                    message_id,
                    delivery["delivery_id"],
                    delivery["recipient"],
                    retryable,
                )
        self.repository.refresh_forward_status(message_id)

    def _send_one(self, mail_from: str, recipient: str, raw_message: bytes, host: str, port: int) -> None:
        with smtplib.SMTP(host=host, port=port, timeout=self.settings.smtp_timeout_seconds) as smtp:
            failures = smtp.sendmail(mail_from, [recipient], raw_message)
            if failures:
                code = next(iter(failures.values()))[0] if failures else None
                error = next(iter(failures.values()))[1] if failures else failures
                exc = smtplib.SMTPResponseException(code or 550, str(error))
                raise exc

    @staticmethod
    def _is_retryable_smtp_error(exc: Exception) -> bool:
        if isinstance(exc, smtplib.SMTPResponseException):
            return 400 <= int(exc.smtp_code) < 500
        if isinstance(exc, (TimeoutError, OSError, ConnectionError, smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError)):
            return True
        return False

    def _backoff_seconds(self, attempts: int, base: float | None = None) -> float:
        base_value = self.settings.queue_retry_base_seconds if base is None else base
        delay = base_value * (2 ** max(0, attempts - 1))
        return min(delay, self.settings.queue_retry_max_seconds)

    def _next_delay_for_message(self, message_id: str) -> float:
        values = self.repository.next_delivery_delays(message_id)
        if not values:
            return self.settings.queue_retry_base_seconds
        return min(values)

    def _is_loop_copy(self, raw_message: bytes) -> bool:
        if not self.loop_token:
            return False
        message = BytesParser(policy=policy.default).parsebytes(raw_message)
        return message.get("X-AI-SMTP-Gateway-Alert") == "1" and message.get("X-AI-SMTP-Gateway-Token") == self.loop_token
