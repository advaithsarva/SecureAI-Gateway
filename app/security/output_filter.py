"""
Phase 6: AI Output Security Filter.
Inspects AI-generated responses for confidential system leakage, unsafe content,
and sensitive PII/secrets before returning the response to the user.
"""
import re
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from app.config import SYNTHETIC_CANARY_MARKERS
from app.security.privacy_scanner import default_privacy_scanner


UNSAFE_OUTPUT_RULES = [
    (
        "OUT-UNSAFE-001",
        "unsafe_policy_violation",
        "CRITICAL",
        re.compile(
            r"(?:EXEC_REVERSE_SHELL_SYNTHETIC_PAYLOAD_DO_NOT_RUN|\[UNSAFE_POLICY_VIOLATING_OUTPUT\]|"
            r"subprocess\.Popen\(\['/bin/sh'|DROP\s+TABLE\s+users\s*;--)",
            re.IGNORECASE,
        ),
        "AI output contained unsafe exploit payload or policy-violating instruction.",
    ),
    (
        "OUT-CONF-001",
        "confidential_system_leak",
        "CRITICAL",
        re.compile(
            r"(?:INTERNAL_SYSTEM_DIRECTIVE_DO_NOT_DISCLOSE|\[MOCK_MODEL_UNPROTECTED_COMPLIANCE\]|"
            r"POLICY-INTERNAL-RESTRICTED-77|sqlite:///synthetic_internal_records\.db)",
            re.IGNORECASE,
        ),
        "AI output attempted to disclose confidential internal system instructions or restricted configuration.",
    ),
]


class OutputFilterResult(BaseModel):
    status: str = Field(..., description="PASSED, REDACTED, or BLOCKED")
    filtered_response: str
    modified: bool = False
    blocked: bool = False
    triggered_rules: List[str] = Field(default_factory=list)
    redacted_entities: Dict[str, int] = Field(default_factory=dict)
    explanation: str


class OutputSecurityFilter:
    """Inspects and sanitizes or blocks AI-generated responses."""

    def inspect_output(self, response_text: str, policy: Optional[Dict[str, Any]] = None) -> OutputFilterResult:
        active_policy = policy or {}
        if not active_policy.get("enable_output_filter", True):
            return OutputFilterResult(
                status="PASSED",
                filtered_response=response_text,
                modified=False,
                blocked=False,
                triggered_rules=[],
                redacted_entities={},
                explanation="Output filter disabled by policy.",
            )

        triggered_rules: List[str] = []
        explanations: List[str] = []
        block_unsafe = active_policy.get("block_unsafe_outputs", True)

        # 1. Check synthetic canary markers
        for marker in SYNTHETIC_CANARY_MARKERS:
            if marker.lower() in response_text.lower():
                triggered_rules.append("OUT-CANARY-001")
                explanations.append("Detected protected synthetic canary marker in model output.")
                break

        # 2. Check unsafe or confidential output rules
        for rule_id, _cat, _sev, pattern, expl in UNSAFE_OUTPUT_RULES:
            if pattern.search(response_text):
                triggered_rules.append(rule_id)
                explanations.append(expl)

        if triggered_rules and block_unsafe:
            return OutputFilterResult(
                status="BLOCKED",
                filtered_response=(
                    "[SecureAI Gateway Output Filter: RESPONSE BLOCKED] "
                    "The AI-generated response was blocked because it violated output security policy "
                    f"({', '.join(triggered_rules)})."
                ),
                modified=True,
                blocked=True,
                triggered_rules=triggered_rules,
                redacted_entities={},
                explanation=" ".join(explanations),
            )

        # 3. Scan and redact sensitive data (PII / secrets) in model output
        priv_scan = default_privacy_scanner.scan_and_redact(response_text, active_policy)
        if priv_scan.detected:
            triggered_rules.extend([m.rule_id for m in priv_scan.matches])
            explanations.append(f"Redacted sensitive data in output: {priv_scan.explanation}")
            return OutputFilterResult(
                status="REDACTED",
                filtered_response=priv_scan.sanitized_text,
                modified=True,
                blocked=False,
                triggered_rules=triggered_rules,
                redacted_entities=priv_scan.entity_counts,
                explanation=" ".join(explanations),
            )

        return OutputFilterResult(
            status="PASSED",
            filtered_response=response_text,
            modified=False,
            blocked=False,
            triggered_rules=[],
            redacted_entities={},
            explanation="AI output passed all confidentiality, policy, and privacy checks.",
        )


default_output_filter = OutputSecurityFilter()
