from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ThreatCategory(str, Enum):
    BENIGN = "BENIGN"
    TERRORISM = "TERRORISM"
    TECHNOGENIC = "TECHNOGENIC"
    ILLEGAL = "ILLEGAL"
    OTHER_THREAT = "OTHER_THREAT"


class Action(str, Enum):
    DELIVER = "DELIVER"
    DELIVER_AND_ALERT = "DELIVER_AND_ALERT"
    REVIEW = "REVIEW"


class AttachmentMeta(BaseModel):
    filename: str = ""
    content_type: str = "application/octet-stream"
    size: int = 0


class EmailDocument(BaseModel):
    message_id: str | None = None
    sender: str = ""
    recipients: list[str] = Field(default_factory=list)
    subject: str = ""
    text: str = ""
    attachments: list[AttachmentMeta] = Field(default_factory=list)

    @field_validator("recipients")
    @classmethod
    def strip_recipients(cls, value: list[str]) -> list[str]:
        return [item.strip() for item in value if item and item.strip()]


class ThreatAssessment(BaseModel):
    is_threat: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = ""
    evidence: list[str] = Field(default_factory=list)


class CategoryAssessment(BaseModel):
    category: ThreatCategory
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = ""
    evidence: list[str] = Field(default_factory=list)


class Classification(BaseModel):
    category: ThreatCategory
    is_threat: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reason: str = ""
    evidence: list[str] = Field(default_factory=list)
    source: str = "AI_TWO_STAGE"
    threat_confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class PolicyDecision(BaseModel):
    action: Action
    category: ThreatCategory
    confidence: float
    destination: str | None = None
    review: bool = False
    reason: str = ""


class ProcessingResult(BaseModel):
    classification: Classification
    decision: PolicyDecision
    processing_time_ms: int


@dataclass(frozen=True)
class GatewaySettings:
    original_smtp_host: str = "mailpit-original"
    original_smtp_port: int = 1025
    alert_smtp_host: str = "mailpit-alert"
    alert_smtp_port: int = 1026
    smtp_timeout_seconds: float = 8.0
    deepseek_model: str = "deepseek-flash"
    deepseek_api_timeout_seconds: float = 8.0
    max_ai_text_chars: int = 6000
    data_dir: str = "./data"
    db_path: str = "./data/gateway.db"
    mode: str = "ENFORCE"
    terrorism_threshold: float = 0.70
    technogenic_threshold: float = 0.60
    illegal_threshold: float = 0.80
    other_threat_threshold: float = 0.75
    terrorism_destination: str = "alerts-terrorism@local.test"
    technogenic_destination: str = "alerts-technogenic@local.test"
    illegal_destination: str = "alerts-illegal@local.test"
    other_threat_destination: str = "alerts-other@local.test"
