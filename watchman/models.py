"""Shared data models for AI Watchman.

The project guide's "Key components" table and "Severity-based auto-response"
section define these core types. Everything is JSON-serializable so the
WebSocket dashboard can stream events and the change log can persist them.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """From the project guide's severity scale: 0 to 10."""

    MINOR = "0"
    LOW = "1"
    LOW_MEDIUM = "2"
    MEDIUM = "3"
    MEDIUM_HIGH = "4"
    MODERATE = "5"
    MODERATE_HIGH = "6"
    HIGH = "7"
    SEVERE = "8"
    CRITICAL = "9"
    CRITICAL_HIGH = "10"


class Source(str, Enum):
    """Where a finding came from."""

    HTTP_REQUEST = "http_request"
    LOG_LINE = "log_line"
    PROCESS_CRASH = "process_crash"


class DetectionType(str, Enum):
    """How a threat was identified."""

    REGEX_SIGNATURE = "regex_signature"
    AI_JUDGEMENT = "ai_judgment"
    HEURISTIC = "heuristic"


class ThreatCategory(str, Enum):
    """Attack types described in the project guide."""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    XXE = "xxe"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    UNKNOWN = "unknown"


class PolicyType(str, Enum):
    """Policies the policy manager can propose (from the guide)."""

    IP_BLOCK = "ip_block"
    RATE_LIMIT = "rate_limit"
    AUTH_REQUIREMENT = "auth_requirement"


class Event(BaseModel):
    """A single observation or finding captured by the watchman.

    Emitted by the sentinel middleware and mirrored into the SQLite change
    log for the audit trail.
    """

    event_id: str = Field(default_factory=lambda: _new_uuid())
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: Source
    component: str = "sentinel"
    severity: str = "0"
    threat_category: ThreatCategory = ThreatCategory.UNKNOWN
    detection_type: DetectionType = DetectionType.REGEX_SIGNATURE
    detail: str = ""
    evidence: dict | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    request_path: str | None = None
    log_line: str | None = None

    model_config = {"frozen": False}

    def model_dump(self, **kwargs):
        data = super().model_dump(**kwargs)
        data["timestamp"] = data["timestamp"].isoformat()
        return data


class Detection(BaseModel):
    """Result of running the threat engine and jailbreak guard."""

    detection_id: str = Field(default_factory=lambda: _new_uuid())
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source: Source
    severity: int = 0  # 0..10 from the project guide's scale
    threat_category: ThreatCategory = ThreatCategory.UNKNOWN
    detection_type: DetectionType
    matched_patterns: list[str] = Field(default_factory=list)
    a_i_explanation: str | None = None
    evidence: dict | None = None

    def is_serious(self) -> bool:
        return self.severity >= 7

    def needs_notification(self) -> bool:
        return self.severity >= 4


class Action(BaseModel):
    """An action taken in response to a detection.

    Emitted whenever the policy engine or code-healing path changes state.
    """

    action_id: str = Field(default_factory=lambda: _new_uuid())
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target: str | None = None
    policy_type: PolicyType | None = None
    action_type: str | None = None
    decision: "Decision" = None
    before_state: dict | None = None
    after_state: dict | None = None
    reason: str | None = None
    applied_by: str = "ai-watchman"

    model_config = {"frozen": False}

    def model_dump(self, **kwargs):
        data = super().model_dump(**kwargs)
        data["timestamp"] = data["timestamp"].isoformat()
        return data


class Decision(BaseModel):
    """The outcome the scoring module recommends."""

    decision_id: str = Field(default_factory=lambda: _new_uuid())
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    severity: int = 0
    threat_category: ThreatCategory = ThreatCategory.UNKNOWN
    recommendation: str = ""
    action: Action | None = None
    requires_human_approval: bool = False
    auto_mitigated: bool = False
    notified: bool = False

    def needs_approval(self) -> bool:
        return self.severity >= 7

    def notify(self) -> bool:
        return self.severity >= 4


def _new_uuid() -> str:
    import uuid

    return uuid.uuid4().hex
