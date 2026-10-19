"""Pydantic data models for the AI Watchman configuration.

These mirror the watchman.yaml schema described in the project guide's
"Configuration file (watchman.yaml)" section.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class LlmProvider(str, Enum):
    """Supported AI providers (from the project guide README).

    groq | openai | anthropic | ollama | cohere | google
    """

    groq = "groq"
    openai = "openai"
    anthropic = "anthropic"
    ollama = "ollama"
    cohere = "cohere"
    google = "google"


class AlertChannel(BaseModel):
    """A single alert channel (Slack webhook or SMTP email)."""

    type: str
    webhook_url: str | None = None
    smtp_host: str | None = None
    from_email: str | None = None
    to_emails: list[str] | None = None


class AlertsConfig(BaseModel):
    """Alert targets from watchman.yaml."""

    channels: list[AlertChannel] = Field(default_factory=list)


class LlmConfig(BaseModel):
    """AI provider configuration."""

    provider: LlmProvider = LlmProvider.groq
    model: str = "llama-3.3-70b-versatile"
    api_key_env_var: str = "GROQ_API_KEY"
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)


class ThreatDetectionConfig(BaseModel):
    """Threat detection thresholds."""

    auto_mitigate_threshold: int = Field(default=7, ge=0, le=10)
    notify_threshold: int = Field(default=4, ge=0, le=10)
    signature_patterns: int = Field(default=120, ge=0)


class PolicyEngineConfig(BaseModel):
    """Policy engine configuration."""

    mode: str = "semi_auto"  # auto | semi_auto | manual
    ip_block_duration_seconds: int = Field(default=3600, ge=0)


class CodeHealingConfig(BaseModel):
    """Code-healing configuration (from the project guide)."""

    enabled: bool = True
    auto_patch: bool = False  # true only for CI/CD; always requires git
    ask_human_threshold: int = Field(default=7, ge=0, le=10)
    max_retries: int = Field(default=3, ge=1)


class WatchmanConfig(BaseModel):
    """Top-level AI Watchman configuration loaded from watchman.yaml."""

    name: str = "ai-watchman"
    version: str = "1.0.0"
    environment: str = "development"

    llm: LlmConfig = Field(default_factory=LlmConfig)
    threat_detection: ThreatDetectionConfig = Field(default_factory=ThreatDetectionConfig)
    policy_engine: PolicyEngineConfig = Field(default_factory=PolicyEngineConfig)
    code_healing: CodeHealingConfig = Field(default_factory=CodeHealingConfig)
    alerts: AlertsConfig = Field(default_factory=AlertsConfig)

    # Safety flag: humans approve serious actions (from the project guide)
    self_heal: bool = False
