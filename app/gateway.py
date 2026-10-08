from __future__ import annotations

import asyncio
import logging
import smtplib
from typing import Any

from app.application.processing_service import EmailProcessor
from app.domain.models import Action, GatewaySettings

LOGGER = logging.getLogger("app.gateway")


class SmtpGatewayHandler:
    def __init__(self, processor: EmailProcessor, settings: GatewaySettings) -> None:
        self.processor = processor
        self.settings = settings

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:
        try:
            record_id, result = await asyncio.to_thread(self._process_and_forward, envelope)
            LOGGER.info(
                "processed id=%s category=%s confidence=%.2f action=%s review=%s source=%s",
                record_id,
                result.classification.category.value,
                result.classification.confidence,
                result.decision.action.value,
                result.decision.review,
                result.classification.source,
            )
            return "250 2.0.0 Message accepted"
        except Exception:
            LOGGER.exception("Gateway processing/forwarding failed")
            return "451 4.3.0 Temporary processing failure"

    def _process_and_forward(self, envelope: Any):
        record_id, _email, result = self.processor.process(envelope.content)
        decision = result.decision
        original_recipients = list(envelope.rcpt_tos)

        if not original_recipients:
            self.processor.repository.update_forward_status(record_id, "ORIGINAL_FAILED", "No original SMTP recipients available")
            raise ValueError("No original SMTP recipients available")

        if self.settings.mode == "AUDIT" or decision.action == Action.DELIVER:
            self._send_original_or_fail(record_id, envelope, original_recipients)
            return record_id, result

        if decision.action == Action.DELIVER_AND_ALERT and decision.destination:
            self._send_original_or_fail(record_id, envelope, original_recipients)

            try:
                self._send(
                    mail_from=envelope.mail_from or "",
                    recipients=[decision.destination],
                    raw_message=envelope.content,
                    host=self.settings.alert_smtp_host,
                    port=self.settings.alert_smtp_port,
                )
                self.processor.repository.update_forward_status(record_id, "ORIGINAL_AND_ALERT_SENT")
            except Exception as exc:
                self.processor.repository.update_forward_status(
                    record_id, "ORIGINAL_SENT_ALERT_FAILED", str(exc)
                )
                LOGGER.exception("Alert copy failed for id=%s", record_id)
            return record_id, result

        self._send_original_or_fail(record_id, envelope, original_recipients)
        return record_id, result

    def _send_original_or_fail(self, record_id: str, envelope: Any, recipients: list[str]) -> None:
        try:
            self._send(
                mail_from=envelope.mail_from or "",
                recipients=recipients,
                raw_message=envelope.content,
                host=self.settings.original_smtp_host,
                port=self.settings.original_smtp_port,
            )
            self.processor.repository.update_forward_status(record_id, "ORIGINAL_SENT")
        except Exception as exc:
            self.processor.repository.update_forward_status(record_id, "ORIGINAL_FAILED", str(exc))
            LOGGER.exception("Original delivery failed for id=%s", record_id)
            raise

    def _send(self, mail_from: str, recipients: list[str], raw_message: bytes, host: str, port: int) -> None:
        if not recipients:
            raise ValueError("No SMTP recipients available")
        with smtplib.SMTP(host=host, port=port, timeout=self.settings.smtp_timeout_seconds) as smtp:
            failures = smtp.sendmail(mail_from, recipients, raw_message)
            if failures:
                raise RuntimeError(f"SMTP delivery rejected for recipients: {failures}")
