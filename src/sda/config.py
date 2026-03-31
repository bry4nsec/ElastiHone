"""Application configuration via pydantic-settings.

Supports runtime configuration updates from the web UI settings page.
"""

from __future__ import annotations

import threading
from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ElasticsearchConfig(BaseSettings):
    """Elasticsearch connection settings."""

    model_config = SettingsConfigDict(env_prefix="SDA_ES_")

    # ── Elasticsearch (9200) ──
    url: str = Field(default="https://localhost:9200", description="Elasticsearch URL")
    api_key: str | None = Field(default=None, description="Elasticsearch API key")
    username: str | None = Field(default=None, description="Basic auth username")
    password: str | None = Field(default=None, description="Basic auth password")
    verify_certs: bool = Field(default=False, description="Verify TLS certificates")
    ca_certs: str | None = Field(default=None, description="Path to CA certificate bundle")

    # ── Kibana (5601) — separate credentials ──
    kibana_url: str = Field(default="", description="Kibana URL (e.g. https://kibana:5601)")
    kibana_space: str = Field(default="", description="Kibana space ID (leave empty for default space)")
    kibana_username: str | None = Field(default=None, description="Kibana basic auth username (if different from ES)")
    kibana_password: str | None = Field(default=None, description="Kibana basic auth password (if different from ES)")
    kibana_api_key: str | None = Field(default=None, description="Kibana API key (if different from ES)")

    # ── Indices & Analysis ──
    production_indices: str = Field(
        default="logs-*",
        description="Comma-separated index patterns for production telemetry (e.g. logs-*,winlogbeat-*,filebeat-*)",
    )
    noise_lookback_days: int = Field(
        default=7, description="Days of historical telemetry to analyse"
    )


class LLMConfig(BaseSettings):
    """LLM provider settings — supports OpenAI-compatible and Anthropic endpoints."""

    model_config = SettingsConfigDict(env_prefix="SDA_LLM_")

    provider: str = Field(
        default="openai",
        description="AI provider: 'openai' (OpenAI-compatible, Azure, etc.) or 'anthropic' (Claude)",
    )
    base_url: str = Field(
        default="https://api.openai.com/v1",
        description="API endpoint URL (OpenAI, Azure OpenAI, or any compatible endpoint)",
    )
    api_key: str = Field(
        default="",
        description="API key for the AI provider",
    )
    deployment_name: str = Field(
        default="gpt-5.2",
        description="Model name (e.g. gpt-5.2, claude-sonnet-4-20250514)",
    )
    max_iterations: int = Field(
        default=3, description="Max optimisation iterations for rule refinement"
    )
    agent_timeout: int = Field(
        default=120, description="AI investigation timeout in seconds"
    )
    temperature: float = Field(default=0.2, description="LLM temperature")


class AppConfig(BaseSettings):
    """Top-level application configuration."""

    model_config = SettingsConfigDict(env_prefix="SDA_")

    debug: bool = Field(default=False, description="Enable debug logging")
    web_host: str = Field(default="0.0.0.0", description="Web UI bind host")
    web_port: int = Field(default=8080, description="Web UI bind port")

    # Verdict thresholds
    approve_tpr_min: float = Field(default=0.9, description="Min TPR for APPROVE verdict")
    approve_fpr_max: float = Field(default=0.01, description="Max FPR for APPROVE verdict")
    review_tpr_min: float = Field(default=0.7, description="Min TPR for REVIEW verdict")
    review_fpr_max: float = Field(default=0.05, description="Max FPR for REVIEW verdict")

    es: ElasticsearchConfig = Field(default_factory=ElasticsearchConfig)
    llm: LLMConfig = Field(default_factory=LLMConfig)


# ─── Runtime Config Singleton ─────────────────────────────────────────────────
# Allows the web UI to update configuration without restarting the process.

_config_lock = threading.Lock()
_runtime_config: AppConfig | None = None


def get_config() -> AppConfig:
    """Load configuration — returns the runtime override if set, else from env."""
    global _runtime_config
    with _config_lock:
        if _runtime_config is not None:
            return _runtime_config
        _runtime_config = AppConfig()
        return _runtime_config


def update_config(**overrides: Any) -> AppConfig:
    """Update runtime configuration with new values.

    Accepts top-level, es.*, and llm.* dotted keys.
    Returns the updated config.
    """
    global _runtime_config
    with _config_lock:
        current = _runtime_config or AppConfig()
        current_dict = current.model_dump()

        for key, value in overrides.items():
            if value is None or value == "":
                continue
            if "." in key:
                section, field = key.split(".", 1)
                if section in current_dict and isinstance(current_dict[section], dict):
                    current_dict[section][field] = value
            else:
                current_dict[key] = value

        _runtime_config = AppConfig(
            **{k: v for k, v in current_dict.items() if k not in ("es", "llm")},
            es=ElasticsearchConfig(**current_dict["es"]),
            llm=LLMConfig(**current_dict["llm"]),
        )
        return _runtime_config


def get_config_display() -> dict:
    """Return config as a dict with sensitive fields masked."""
    cfg = get_config()
    data = cfg.model_dump(mode="json")
    # Mask secrets
    if data["es"].get("api_key"):
        data["es"]["api_key"] = data["es"]["api_key"][:8] + "••••••••"
    if data["es"].get("password"):
        data["es"]["password"] = "••••••••"
    if data["es"].get("kibana_password"):
        data["es"]["kibana_password"] = "••••••••"
    if data["es"].get("kibana_api_key"):
        v = data["es"]["kibana_api_key"]
        data["es"]["kibana_api_key"] = v[:8] + "••••••••" if len(v) > 8 else "••••••••"
    if data["llm"].get("api_key"):
        v = data["llm"]["api_key"]
        data["llm"]["api_key"] = v[:8] + "••••••••" if len(v) > 8 else "••••••••"
    return data
