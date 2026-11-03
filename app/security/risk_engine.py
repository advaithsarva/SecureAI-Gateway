"""
Phase 4: Central Risk Assessment Engine.

Combines prompt injection scan results and privacy/sensitive-data scan results
into a unified 0-100 risk score, risk level classification, and gateway decision
(ALLOW, SANITIZE, BLOCK) with transparent reasoning.
"""
from typing import Dict, Any, List
from pydantic import BaseModel, Field

from app.config import DEFAULT_SECURITY_POLICY
from app.security.prompt_scanner import PromptScanResult, default_prompt_scanner
from app.security.privacy_scanner import PrivacyScanResult, default_privacy_scanner


class RiskAssessmentResult(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=100.0)
    risk_level: str = Field(..., description="Low Risk, Medium Risk, High Risk, or Critical Risk")
    decision: str = Field(..., description="ALLOW, SANITIZE, or BLOCK")
    decision_reason: str
    threat_category: str
    sanitized_prompt: str
    matched_rules: List[str] = Field(default_factory=list)
    prompt_scan: PromptScanResult
    privacy_scan: PrivacyScanResult


def classify_risk_level(score: float) -> str:
    """
    Classification bands specified in Phase 4:
    - 0-29: Low Risk
    - 30-59: Medium Risk
    - 60-79: High Risk
    - 80-100: Critical Risk
    """
    if score < 30.0:
        return "Low Risk"
    if score < 60.0:
        return "Medium Risk"
    if score < 80.0:
        return "High Risk"
    return "Critical Risk"


class RiskAssessmentEngine:
    """Configurable central risk engine combining all input security scanners."""

    def assess(self, prompt: str, policy: Dict[str, Any] | None = None) -> RiskAssessmentResult:
        active_policy = dict(DEFAULT_SECURITY_POLICY)
        if policy:
            active_policy.update(policy)

        enable_prompt = active_policy.get("enable_prompt_scanner", True)
        enable_privacy = active_policy.get("enable_privacy_scanner", True)
        prompt_weight = float(active_policy.get("prompt_weight", 1.0))
        privacy_weight = float(active_policy.get("privacy_weight", 1.0))
        block_threshold = float(active_policy.get("block_threshold", 60.0))
        sanitize_threshold = float(active_policy.get("sanitize_threshold", 30.0))
        block_on_critical_secrets = bool(active_policy.get("block_on_critical_secrets", False))

        if enable_prompt:
            p_res = default_prompt_scanner.scan(prompt)
        else:
            p_res = PromptScanResult(
                detected=False,
                risk_category="benign",
                severity="NONE",
                matched_rules=[],
                explanation="Prompt injection scanner disabled by policy.",
                raw_score=0.0,
            )

        if enable_privacy:
            priv_res = default_privacy_scanner.scan_and_redact(prompt, active_policy)
        else:
            priv_res = PrivacyScanResult(
                detected=False,
                sanitized_text=prompt,
                risk_category="none",
                severity="NONE",
                matches=[],
                entity_counts={},
                raw_score=0.0,
                explanation="Privacy scanner disabled by policy.",
            )

        weighted_prompt_score = p_res.raw_score * prompt_weight
        weighted_privacy_score = priv_res.raw_score * privacy_weight

        # If only privacy entities were detected (and no prompt injection) and block_on_critical_secrets is False,
        # keep pure privacy score within the Medium Risk (SANITIZE) band unless combined with injection
        if priv_res.detected and not p_res.detected and not block_on_critical_secrets:
            combined_score = min(58.0, round(weighted_privacy_score + weighted_prompt_score, 2))
        else:
            # Combine highest weighted score + 35% of secondary scanner score
            hi = max(weighted_prompt_score, weighted_privacy_score)
            lo = min(weighted_prompt_score, weighted_privacy_score)
            combined_score = min(100.0, round(hi + lo * 0.35, 2))

        risk_level = classify_risk_level(combined_score)

        matched_rule_ids = [r.rule_id for r in p_res.matched_rules] + [
            m.rule_id for m in priv_res.matches
        ]

        # Determine primary threat category
        if p_res.detected and priv_res.detected:
            threat_category = f"{p_res.risk_category}+{priv_res.risk_category}"
        elif p_res.detected:
            threat_category = p_res.risk_category
        elif priv_res.detected:
            threat_category = priv_res.risk_category
        else:
            threat_category = "benign"

        # Decision logic: ALLOW, SANITIZE, or BLOCK
        if p_res.detected and combined_score >= block_threshold:
            decision = "BLOCK"
            decision_reason = (
                f"Blocked due to prompt security violation ({p_res.risk_category}). "
                f"Risk score {combined_score}/100 ({risk_level}) exceeds block threshold ({block_threshold}). "
                f"{p_res.explanation}"
            )
        elif priv_res.detected and block_on_critical_secrets and combined_score >= block_threshold:
            decision = "BLOCK"
            decision_reason = (
                f"Blocked under strict secret policy ({priv_res.risk_category}). "
                f"Risk score {combined_score}/100 ({risk_level}) exceeds block threshold ({block_threshold}). "
                f"{priv_res.explanation}"
            )
        elif priv_res.detected and priv_res.sanitized_text != prompt:
            decision = "SANITIZE"
            decision_reason = (
                f"Sanitized sensitive information prior to model invocation. "
                f"Risk score {combined_score}/100 ({risk_level}). {priv_res.explanation}"
            )
        elif combined_score >= block_threshold:
            decision = "BLOCK"
            decision_reason = (
                f"Blocked because risk score {combined_score}/100 ({risk_level}) "
                f"exceeds configured block threshold ({block_threshold})."
            )
        elif combined_score >= sanitize_threshold:
            decision = "SANITIZE"
            decision_reason = (
                f"Sanitized/flagged as Medium Risk ({combined_score}/100 >= {sanitize_threshold})."
            )
        else:
            decision = "ALLOW"
            if p_res.benign_context_dampened:
                decision_reason = (
                    f"Allowed (Risk Score {combined_score}/100 - {risk_level}): "
                    f"{p_res.explanation}"
                )
            else:
                decision_reason = (
                    f"Allowed (Risk Score {combined_score}/100 - {risk_level}): "
                    "No policy violations or sensitive data exposures detected."
                )

        return RiskAssessmentResult(
            risk_score=combined_score,
            risk_level=risk_level,
            decision=decision,
            decision_reason=decision_reason,
            threat_category=threat_category,
            sanitized_prompt=priv_res.sanitized_text,
            matched_rules=matched_rule_ids,
            prompt_scan=p_res,
            privacy_scan=priv_res,
        )


default_risk_engine = RiskAssessmentEngine()
