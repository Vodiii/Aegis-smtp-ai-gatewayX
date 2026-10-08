from __future__ import annotations

import asyncio
import logging
import secrets
import smtplib
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses
from typing import Any

from app.application.processing_service import EmailProcessor
from app.domain.models import Action, GatewaySettings, ProcessingResult
from app.infrastructure.database.repository import MessageRepository

LOGGER = logging.getLogger("app.gateway")


class SmtpGatewayHandler:
    def __init__(self, processor: EmailProcessor, settings: GatewaySettings) -> None:
        self.processor = processor
        self.settings = settings
        self.loop_token = settings.gateway_loop_token or secrets.token_urlsafe(24)

    async def handle_RCPT(self, server: Any, session: Any, envelope: Any, address: str, rcpt_options: Any) -> str:
        normalized = address.strip().lower()
        if "@" not in normalized:
            return "553 5.1.3 Invalid recipient address"
        local, domain = normalized.rsplit("@", 1)
        if not local or not domain or domain not in self.settings.allowed_recipient_domains:
            return "550 5.7.1 Relaying denied for recipient domain"
        if len(envelope.rcpt_tos) >= self.settings.max_recipients:
            return "452 4.5.3 Too many recipients"
        envelope.rcpt_tos.append(address)
        return "250 2.1.5 Recipient OK"

    async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:
        try:
            raw_message = bytes(envelope.content or b"")
            if len(raw_message) > self.settings.max_message_size_bytes:
                return "552 5.3.4 Message exceeds gateway size limit"
            if self._is_loop_copy(raw_message):
                LOGGER.error("Gateway loop marker detected; refusing to process message")
                return "550 5.4.6 Mail routing loop detected"

            delivery_key = MessageRepository.make_delivery_key(
                raw_message, envelope.mail_from or "", list(envelope.rcpt_tos)
            )
            existing = self.processor.repository.find_by_delivery_key(delivery_key)
            if existing:
                action = existing["forward_status"]
                if action in {"ORIGINAL_SENT", "ORIGINAL_AND_ALERT_SENT"}:
                    result = self.processor.repository.to_processing_result(existing["id"])
                    if result:
                        LOGGER.info("idempotent replay id=%s status=%s", existing["id"], action)
                        return "250 2.0.0 Message previously accepted"
                if action == "ORIGINAL_SENT_ALERT_FAILED" and existing.get("destination"):
                    await asyncio.to_thread(self._retry_alert_only, existing["id"], existing, raw_message, envelope)
                    return "250 2.0.0 Message previously delivered; alert copy retried"

            record_id, result = await asyncio.to_thread(
                self._process_and_forward, envelope, delivery_key
            )
            LOGGER.info(
                "processed id=%s category=%s confidence=%.2f action=%s review=%s source=%s status=%s processing_ms=%d",
                record_id,
                result.classification.category.value,
                result.classification.confidence,
                result.decision.action.value,
                result.decision.review,
                result.classification.source,
                self.processor.repository.get(record_id)["forward_status"],
                result.processing_time_ms,
            )
            return "250 2.0.0 Message accepted"
        except InvalidSmtpInput as exc:
            LOGGER.warning("SMTP input rejected: %s", exc)
            return str(exc)
        except OriginalDeliveryTemporaryFailure:
            return "451 4.3.0 Temporary downstream delivery failure"
        except Exception:
            LOGGER.exception("Gateway processing/forwarding failed")
            return "451 4.3.0 Temporary processing failure"

    def _process_and_forward(self, envelope: Any, delivery_key: str | None = None) -> tuple[str, ProcessingResult]:
        original_recipients = list(envelope.rcpt_tos)
        if not original_recipients:
            raise InvalidSmtpInput("553 5.1.3 No valid recipients")

        if delivery_key is None:
            record_id, _email, result = self.processor.process(bytes(envelope.content))
        else:
            record_id, _email, result = self.processor.process(
                bytes(envelope.content), delivery_key=delivery_key
            )
        decision = result.decision

        # The original message is always delivered. In AUDIT mode the alert copy
        # is suppressed, but the AI decision remains available in audit logs.
        self._send_original_or_fail(record_id, envelope, original_recipients)

        if self.settings.mode != "AUDIT" and decision.action == Action.DELIVER_AND_ALERT and decision.destination:
            try:
                alert_message = self._build_alert_copy(bytes(envelope.content), decision.destination)
                self._send(
                    mail_from=envelope.mail_from or "",
                    recipients=[decision.destination],
                    raw_message=alert_message,
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

    def _retry_alert_only(self, record_id: str, existing: dict[str, Any], raw_message: bytes, envelope: Any) -> None:
        destination = existing.get("destination")
        if not destination:
            return
        alert_message = self._build_alert_copy(raw_message, destination)
        self._send(
            mail_from=envelope.mail_from or existing.get("sender") or "",
            recipients=[destination],
            raw_message=alert_message,
            host=self.settings.alert_smtp_host,
            port=self.settings.alert_smtp_port,
        )
        self.processor.repository.update_forward_status(record_id, "ORIGINAL_AND_ALERT_SENT")

    def _send_original_or_fail(self, record_id: str, envelope: Any, recipients: list[str]) -> None:
        try:
            self._send(
                mail_from=envelope.mail_from or "",
                recipients=recipients,
                raw_message=bytes(envelope.content),
                host=self.settings.original_smtp_host,
                port=self.settings.original_smtp_port,
            )
            self.processor.repository.update_forward_status(record_id, "ORIGINAL_SENT")
        except Exception as exc:
            self.processor.repository.update_forward_status(record_id, "ORIGINAL_FAILED", str(exc))
            LOGGER.exception("Original delivery failed for id=%s", record_id)
            raise OriginalDeliveryTemporaryFailure from exc

    def _send(self, mail_from: str, recipients: list[str], raw_message: bytes, host: str, port: int) -> None:
        if not recipients:
            raise InvalidSmtpInput("553 5.1.3 No SMTP recipients available")
        with smtplib.SMTP(host=host, port=port, timeout=self.settings.smtp_timeout_seconds) as smtp:
            failures = smtp.sendmail(mail_from, recipients, raw_message)
            if failures:
                raise RuntimeError(f"SMTP delivery rejected for recipients: {failures}")

    def _is_loop_copy(self, raw_message: bytes) -> bool:
        message = BytesParser(policy=policy.default).parsebytes(raw_message)
        return message.get("X-AI-SMTP-Gateway-Alert") == "1" and message.get("X-AI-SMTP-Gateway-Token") == self.loop_token

    def _build_alert_copy(self, raw_message: bytes, destination: str) -> bytes:
        message = BytesParser(policy=policy.default).parsebytes(raw_message)
        # Only the alert copy is annotated; the original recipient gets the
        # original bytes unchanged.
        message["X-AI-SMTP-Gateway-Alert"] = "1"
        message["X-AI-SMTP-Gateway-Token"] = self.loop_token
        message["X-AI-SMTP-Gateway-Alert-Recipient"] = destination
        return message.as_bytes(policy=policy.SMTP)


class InvalidSmtpInput(Exception):
    pass


class OriginalDeliveryTemporaryFailure(Exception):
    pass
