"""
Phase 3: Sensitive Data (PII & Secret) Detection and Configurable Redaction Engine.

Security Guarantee:
Raw sensitive values are never stored in findings or audit logs; only masked
placeholders and entity counts are recorded.
"""
import re
from dataclasses import dataclass
from typing import Dict, List, Any, Optional
from pydantic import BaseModel, Field


@dataclass
class PrivacyRule:
    rule_id: str
    entity_type: str
    category: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    weight: float
    placeholder: str
    policy_toggle_key: str
    pattern: str
    explanation: str
    compiled: re.Pattern


class PrivacyMatchInfo(BaseModel):
    rule_id: str
    entity_type: str
    category: str
    severity: str
    weight: float
    count: int
    placeholder: str
    explanation: str


class PrivacyScanResult(BaseModel):
    detected: bool
    sanitized_text: str
    risk_category: str = Field(..., description="Primary privacy risk category or 'none'")
    severity: str = Field(..., description="NONE, LOW, MEDIUM, HIGH, or CRITICAL")
    matches: List[PrivacyMatchInfo] = Field(default_factory=list)
    entity_counts: Dict[str, int] = Field(default_factory=dict)
    raw_score: float = Field(0.0, ge=0.0, le=100.0)
    explanation: str


SEVERITY_RANK = {"NONE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class PrivacyScanner:
    """Configurable pattern-based sensitive-data detector and automatic redactor."""

    def __init__(self) -> None:
        self._rules: Dict[str, PrivacyRule] = {}
        self._load_default_rules()

    def _load_default_rules(self) -> None:
        default_specs = [
            (
                "PRIV-APIKEY",
                "API_KEY",
                "secret_exposure",
                "CRITICAL",
                65.0,
                "[REDACTED_API_KEY]",
                "redact_secrets",
                r"\b(?:sk-[A-Za-z0-9\-_]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z\-_]{25,}|xox[baprs]-[A-Za-z0-9\-]{16,})\b",
                "Detects API keys and cloud provider access tokens.",
            ),
            (
                "PRIV-PASSWORD",
                "PASSWORD",
                "secret_exposure",
                "HIGH",
                55.0,
                "[REDACTED_PASSWORD]",
                "redact_secrets",
                r"(?<=\b(?:password|passwd|pwd|passcode|client_secret|api_secret)\s*(?:is|=|:)\s*)(?:['\"][^'\"]{4,}['\"]|[^\s,.;'\"]{4,})",
                "Detects password or secret assignments in text.",
            ),
            (
                "PRIV-EMAIL",
                "EMAIL",
                "personal_identifiable_info",
                "MEDIUM",
                35.0,
                "[REDACTED_EMAIL]",
                "redact_emails",
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
                "Detects personal or corporate email addresses.",
            ),
            (
                "PRIV-PHONE",
                "PHONE",
                "personal_identifiable_info",
                "MEDIUM",
                35.0,
                "[REDACTED_PHONE]",
                "redact_phones",
                r"(?:(?:\+91|91)[\s\-]?)?\b[6-9]\d{4}[\s\-]?\d{5}\b|(?:\+\d{1,4}[\s\-.]?)?\(?\d{3}\)?[\s\-.]\d{3}[\s\-.]\d{4}\b|\+\d{1,4}[\s\-.]\d{1,4}[\s\-.]\d{3,4}[\s\-.]\d{3,4}\b|\(\d{2,4}\)[\s\-.]?\d{3,4}[\s\-.]\d{4}\b|\b0\d{2,4}[\s.]\d{5,7}\b",
                "Detects Indian 10-digit mobile numbers (+91/6-9xxxxxxxxx) and international phone numbers.",
            ),
            (
                "PRIV-ID-PAN",
                "ID_NUMBER",
                "government_identifier",
                "HIGH",
                48.0,
                "[REDACTED_ID]",
                "redact_ids",
                r"\b[A-Z]{5}[0-9]{4}[A-Z]\b|\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b|\b[2-9]\d{3}[\s\-]\d{4}[\s\-]\d{4}\b|\b\d{3}\.\d{4}\.\d{4}\b|\b\d{11,19}\b",
                "Detects Indian PAN, 12-digit Aadhaar, SSN, and 11-19 digit payment/national ID numbers.",
            ),
            (
                "PRIV-IP",
                "IP_ADDRESS",
                "network_identifier",
                "LOW",
                28.0,
                "[REDACTED_IP]",
                "redact_ips",
                r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b",
                "Detects IPv4 network addresses.",
            ),
        ]

        # Note: Python's standard `re` requires fixed-width lookbehinds, so for PRIV-PASSWORD
        # we handle substitution cleanly via a dedicated regex with group preservation.
        for rule_id, entity_type, cat, sev, weight, placeholder, toggle_key, pat, expl in default_specs:
            if rule_id == "PRIV-PASSWORD":
                pat = (
                    r"(?i:\b((?:password|passwd|pwd|passcode|client_secret|api_secret)\s*(?:is|=|:)\s*))"
                    r"(['\"][^'\"]{4,}['\"]|[^\s,.;'\"]{4,})"
                    r"|\b(?=[A-Za-z0-9_]*[A-Z])(?=[A-Za-z0-9_]*[a-z])(?=[A-Za-z0-9_]*\d)[A-Za-z0-9_]{11,20}\b"
                )
            self.register_rule(
                rule_id=rule_id,
                entity_type=entity_type,
                category=cat,
                severity=sev,
                weight=weight,
                placeholder=placeholder,
                policy_toggle_key=toggle_key,
                pattern=pat,
                explanation=expl,
            )

    def register_rule(
        self,
        rule_id: str,
        entity_type: str,
        category: str,
        severity: str,
        weight: float,
        placeholder: str,
        policy_toggle_key: str,
        pattern: str,
        explanation: str,
    ) -> None:
        compiled = re.compile(pattern, re.IGNORECASE if entity_type not in ("ID_NUMBER", "PASSWORD") else 0)
        self._rules[rule_id] = PrivacyRule(
            rule_id=rule_id,
            entity_type=entity_type,
            category=category,
            severity=severity.upper(),
            weight=float(weight),
            placeholder=placeholder,
            policy_toggle_key=policy_toggle_key,
            pattern=pattern,
            explanation=explanation,
            compiled=compiled,
        )

    def scan_and_redact(self, text: str, policy: Optional[Dict[str, Any]] = None) -> PrivacyScanResult:
        if not text:
            return PrivacyScanResult(
                detected=False,
                sanitized_text="",
                risk_category="none",
                severity="NONE",
                matches=[],
                entity_counts={},
                raw_score=0.0,
                explanation="Empty input; no sensitive data detected.",
            )

        active_policy = policy or {}
        if not active_policy.get("enable_privacy_scanner", True):
            return PrivacyScanResult(
                detected=False,
                sanitized_text=text,
                risk_category="none",
                severity="NONE",
                matches=[],
                entity_counts={},
                raw_score=0.0,
                explanation="Privacy scanner disabled by active policy.",
            )

        sanitized = text
        matches_info: List[PrivacyMatchInfo] = []
        entity_counts: Dict[str, int] = {}

        for rule in self._rules.values():
            should_redact = active_policy.get(rule.policy_toggle_key, True)
            if rule.rule_id == "PRIV-PASSWORD" and not any(
                k in sanitized.lower() for k in ("password", "passwd", "pwd", "passcode", "secret", "email asking for your")
            ):
                continue
            found = list(rule.compiled.finditer(sanitized))
            if not found:
                continue

            count = len(found)
            entity_counts[rule.entity_type] = entity_counts.get(rule.entity_type, 0) + count

            matches_info.append(
                PrivacyMatchInfo(
                    rule_id=rule.rule_id,
                    entity_type=rule.entity_type,
                    category=rule.category,
                    severity=rule.severity,
                    weight=rule.weight,
                    count=count,
                    placeholder=rule.placeholder,
                    explanation=rule.explanation,
                )
            )

            if should_redact:
                if rule.rule_id == "PRIV-PASSWORD":
                    sanitized = rule.compiled.sub(
                        lambda m: f"{m.group(1)}{rule.placeholder}" if m.group(1) else rule.placeholder,
                        sanitized,
                    )
                else:
                    sanitized = rule.compiled.sub(rule.placeholder, sanitized)

        if not matches_info:
            return PrivacyScanResult(
                detected=False,
                sanitized_text=sanitized,
                risk_category="none",
                severity="NONE",
                matches=[],
                entity_counts={},
                raw_score=0.0,
                explanation="No sensitive personal data or credentials detected.",
            )

        matches_info.sort(key=lambda m: m.weight, reverse=True)
        primary_category = matches_info[0].category
        highest_severity = max(matches_info, key=lambda m: SEVERITY_RANK.get(m.severity, 0)).severity

        # Score calculation: primary entity full weight + 20% of additional entity types
        raw_score = min(
            100.0,
            round(matches_info[0].weight + sum(m.weight * 0.20 for m in matches_info[1:]), 2),
        )

        summary_parts = [f"{m.entity_type} ({m.count})" for m in matches_info]
        explanation = f"Detected and redacted sensitive entities: {', '.join(summary_parts)}."

        return PrivacyScanResult(
            detected=True,
            sanitized_text=sanitized,
            risk_category=primary_category,
            severity=highest_severity,
            matches=matches_info,
            entity_counts=entity_counts,
            raw_score=raw_score,
            explanation=explanation,
        )


default_privacy_scanner = PrivacyScanner()
