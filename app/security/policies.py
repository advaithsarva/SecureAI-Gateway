"""Configurable security policies, presets, and Pydantic policy schemas."""
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from app.config import DEFAULT_SECURITY_POLICY


SENSITIVITY_PRESETS: Dict[str, Dict[str, Any]] = {
    "strict": {
        "sensitivity": "strict",
        "block_threshold": 45.0,
        "sanitize_threshold": 20.0,
        "prompt_weight": 1.25,
        "privacy_weight": 1.15,
        "block_on_critical_secrets": True,
    },
    "balanced": {
        "sensitivity": "balanced",
        "block_threshold": 60.0,
        "sanitize_threshold": 30.0,
        "prompt_weight": 1.0,
        "privacy_weight": 1.0,
        "block_on_critical_secrets": False,
    },
    "permissive": {
        "sensitivity": "permissive",
        "block_threshold": 78.0,
        "sanitize_threshold": 40.0,
        "prompt_weight": 0.85,
        "privacy_weight": 0.9,
        "block_on_critical_secrets": False,
    },
}


class SecurityPolicyConfig(BaseModel):
    sensitivity: str = Field("balanced", description="strict, balanced, or permissive")
    block_threshold: float = Field(60.0, ge=10.0, le=100.0)
    sanitize_threshold: float = Field(30.0, ge=5.0, le=95.0)
    enable_prompt_scanner: bool = True
    enable_ml_heuristic_boost: bool = True
    enable_privacy_scanner: bool = True
    redact_emails: bool = True
    redact_phones: bool = True
    redact_ids: bool = True
    redact_ips: bool = True
    redact_secrets: bool = True
    block_on_critical_secrets: bool = False
    enable_output_filter: bool = True
    block_unsafe_outputs: bool = True
    max_prompt_length: int = Field(12000, ge=50, le=50000)
    max_request_bytes: int = Field(65536, ge=512, le=524288)
    rate_limit_per_minute: int = Field(60, ge=1, le=10000)
    model_provider: str = Field("mock", description="mock or ollama")
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.2"
    prompt_weight: float = Field(1.0, ge=0.1, le=3.0)
    privacy_weight: float = Field(1.0, ge=0.1, le=3.0)


def apply_sensitivity_preset(policy: Dict[str, Any], preset_name: Optional[str] = None) -> Dict[str, Any]:
    merged = dict(DEFAULT_SECURITY_POLICY)
    merged.update(policy)
    if preset_name and preset_name in SENSITIVITY_PRESETS:
        merged.update(SENSITIVITY_PRESETS[preset_name])
    return merged
