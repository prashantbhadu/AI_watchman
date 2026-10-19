"""Load the watchman configuration from watchman.yaml.

Usage::

    from watchman.config import load_config

    config = load_config("watchman.yaml")
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml
from pydantic import BaseModel

from .config_models import WatchmanConfig


def _default_config_path() -> Path:
    """Find watchman.yaml, searching the project root first, then the cwd."""
    candidates = [
        Path.cwd() / "watchman.yaml",
        Path.cwd() / "ai-watchman" / "watchman.yaml",
        Path(__file__).resolve().parents[2] / "watchman.yaml",
    ]
    for path in candidates:
        if path.exists():
            return path
    return Path.cwd() / "watchman.yaml"


def _merge(user: dict, default: BaseModel) -> dict:
    """Deep-merge a user doc over the Pydantic defaults."""

    def _merge_dicts(user_dict: dict, default_dict: dict) -> dict:
        merged = dict(default_dict)
        for key, value in user_dict.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key] = _merge_dicts(value, merged[key])
            else:
                merged[key] = value
        return merged

    return _merge_dicts(user, default.model_dump())


def load_config(path: str | os.PathLike[str] | None = None) -> WatchmanConfig:
    """Load and validate the configuration file.

    Falls back to Pydantic defaults when keys are missing, so every field
    from :class:`WatchmanConfig` is always available.
    """

    if path is None:
        path = os.environ.get("WATCHMAN_CONFIG", str(_default_config_path()))

    path = Path(path)
    if not path.exists():
        return WatchmanConfig()  # returns fully-typed defaults

    with open(path, "r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    merged = _merge(raw, WatchmanConfig())
    return WatchmanConfig(**merged)
