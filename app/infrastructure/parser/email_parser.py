from __future__ import annotations

from email import policy
from email.header import decode_header, make_header
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses

from bs4 import BeautifulSoup

from app.domain.models import AttachmentMeta, EmailDocument


def _decode(value: str | None) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


class EmailParser:
    def __init__(self, max_text_chars: int = 6000) -> None:
        self.max_text_chars = max_text_chars

    def parse(self, raw_message: bytes) -> EmailDocument:
        message = BytesParser(policy=policy.default).parsebytes(raw_message)

        sender = getaddresses([message.get("From", "")])
        sender_value = sender[0][1] if sender else ""
        recipients = [address for _, address in getaddresses(message.get_all("To", []) + message.get_all("Cc", []))]

        plain_parts: list[str] = []
        html_parts: list[str] = []
        attachments: list[AttachmentMeta] = []

        for part in message.walk():
            if part.is_multipart():
                continue

            filename = part.get_filename()
            disposition = part.get_content_disposition()
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True) or b""

            if filename or disposition == "attachment":
                attachments.append(
                    AttachmentMeta(
                        filename=_decode(filename),
                        content_type=content_type,
                        size=len(payload),
                    )
                )
                continue

            if content_type == "text/plain":
                plain_parts.append(_decode_part(part))
            elif content_type == "text/html":
                html_parts.append(_decode_part(part))

        if plain_parts:
            body = "\n\n".join(plain_parts)
        else:
            body = "\n\n".join(
                BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
                for html in html_parts
            )

        body = body.strip()
        if len(body) > self.max_text_chars:
            body = body[: self.max_text_chars]

        return EmailDocument(
            message_id=_decode(message.get("Message-ID")) or None,
            sender=sender_value,
            recipients=recipients,
            subject=_decode(message.get("Subject")),
            text=body,
            attachments=attachments,
        )
