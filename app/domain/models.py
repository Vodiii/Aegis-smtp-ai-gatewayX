from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

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


class RiskAssessment(BaseModel):
    score: float = Field(ge=0.0, le=1.0)
    requires_ai: bool
    keywords: list[str] = Field(default_factory=list)
    phrases: list[str] = Field(default_factory=list)
    char_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    obfuscation_detected: bool = False
    reason: str = ""


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
    processing_started_at: datetime | None = None
    processing_finished_at: datetime | None = None
    risk_assessment: RiskAssessment | None = None


@dataclass(frozen=True)
class GatewaySettings:
    original_smtp_host: str = "mailpit-original"
    original_smtp_port: int = 1025
    alert_smtp_host: str = "mailpit-alert"
    alert_smtp_port: int = 1026
    smtp_timeout_seconds: float = 8.0
    deepseek_model: str = "deepseek-flash"
    deepseek_api_timeout_seconds: float = 8.0
    deepseek_max_retries: int = 1
    deepseek_retry_backoff_seconds: float = 0.35
    max_ai_text_chars: int = 6000
    max_message_size_bytes: int = 10 * 1024 * 1024
    max_recipients: int = 50
    max_attachments: int = 20
    allowed_recipient_domains: tuple[str, ...] = ("local.test",)
    gateway_loop_token: str = ""
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
    risk_ai_threshold: float = 0.22
    risk_low_threshold: float = 0.08
    risk_char_threshold: float = 0.75
    risk_require_ai_on_obfuscation: bool = True
    risk_training_path: str = "./config/risk_training.json"
    queue_poll_interval_seconds: float = 0.25
    queue_retry_base_seconds: float = 1.0
    queue_retry_max_seconds: float = 60.0
    queue_stale_seconds: float = 120.0
    queue_max_attempts: int = 20
    delivery_retry_base_seconds: float = 2.0
    delivery_max_attempts: int = 8
