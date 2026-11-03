"""
Core SecureAI Gateway Pipeline Orchestrator.
Implements the complete Input Inspection -> Risk Assessment -> Model Adapter ->
Output Security Filter -> Audit Logging flow, plus an Unprotected Baseline runner
for Experiment A vs. Experiment B evaluation.
"""
from datetime import datetime, timezone
from pathlib import Path
import time
import uuid
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field

from app.config import DB_PATH
from app.database.audit_logger import insert_audit_event
from app.database.db import load_active_policy
from app.security.output_filter import OutputFilterResult, default_output_filter
from app.security.rate_limiter import default_rate_limiter, validate_incoming_request
from app.security.risk_engine import RiskAssessmentResult, classify_risk_level, default_risk_engine
from app.services.model_adapter import default_model_router


class GatewayRequest(BaseModel):
    prompt: str = Field(..., description="User input prompt")
    client_id: str = Field("default-client", description="Client or session identifier")
    policy_override: Optional[Dict[str, Any]] = Field(None, description="Optional per-request policy override")


class GatewayResponse(BaseModel):
    request_id: str
    timestamp: str
    client_id: str
    redacted_prompt: str
    risk_score: float
    risk_level: str
    threat_category: str
    matched_security_rules: List[str] = Field(default_factory=list)
    gateway_decision: str = Field(..., description="ALLOW, SANITIZE, or BLOCK")
    decision_reason: str
    model_provider: str
    ai_response: str
    output_inspection_result: str = Field(..., description="PASSED, REDACTED, BLOCKED, or SKIPPED")
    output_filter_details: Optional[OutputFilterResult] = None
    risk_details: Optional[RiskAssessmentResult] = None
    processing_latency_ms: float
    final_request_status: str


def process_gateway_request(
    req: GatewayRequest,
    db_path: Path = DB_PATH,
    record_audit: bool = True,
    enforce_rate_limit: bool = True,
) -> GatewayResponse:
    """Execute the full SecureAI Gateway pipeline on an incoming request."""
    start_ns = time.perf_counter_ns()
    request_id = f"req-{uuid.uuid4().hex[:12]}"
    timestamp = datetime.now(timezone.utc).isoformat()

    policy = load_active_policy(db_path)
    if req.policy_override:
        policy.update(req.policy_override)

    # 1. Request Validation
    raw_bytes = len((req.prompt or "").encode("utf-8", errors="ignore"))
    val_check = validate_incoming_request(req.prompt, raw_body_bytes=raw_bytes, policy=policy)
    if not val_check.valid:
        elapsed_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 3)
        resp = GatewayResponse(
            request_id=request_id,
            timestamp=timestamp,
            client_id=req.client_id,
            redacted_prompt="[INVALID_REQUEST_REJECTED]",
            risk_score=65.0,
            risk_level="High Risk",
            threat_category="request_validation_error",
            matched_security_rules=[f"VAL-{val_check.status_code}"],
            gateway_decision="BLOCK",
            decision_reason=val_check.reason,
            model_provider="none",
            ai_response=f"[SecureAI Gateway Request Rejected] {val_check.reason}",
            output_inspection_result="SKIPPED",
            output_filter_details=None,
            risk_details=None,
            processing_latency_ms=elapsed_ms,
            final_request_status=f"REJECTED_{val_check.status_code}",
        )
        if record_audit:
            insert_audit_event(
                {
                    **resp.model_dump(),
                    "redacted_response": resp.ai_response,
                    "entity_counts": {},
                },
                db_path=db_path,
            )
        return resp

    # 2. Rate Limiting
    if enforce_rate_limit:
        rate_limit_max = int(policy.get("rate_limit_per_minute", 60))
        allowed_rate, _rem, retry_after = default_rate_limiter.check_rate_limit(
            req.client_id, max_requests=rate_limit_max
        )
        if not allowed_rate:
            elapsed_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 3)
            reason = f"Rate limit exceeded ({rate_limit_max} requests/min). Retry after {retry_after}s."
            resp = GatewayResponse(
                request_id=request_id,
                timestamp=timestamp,
                client_id=req.client_id,
                redacted_prompt="[RATE_LIMITED_REQUEST]",
                risk_score=70.0,
                risk_level="High Risk",
                threat_category="rate_limit_exceeded",
                matched_security_rules=["RATE-LIMIT-429"],
                gateway_decision="BLOCK",
                decision_reason=reason,
                model_provider="none",
                ai_response=f"[SecureAI Gateway Rate Limit] {reason}",
                output_inspection_result="SKIPPED",
                output_filter_details=None,
                risk_details=None,
                processing_latency_ms=elapsed_ms,
                final_request_status="RATE_LIMITED_429",
            )
            if record_audit:
                insert_audit_event(
                    {
                        **resp.model_dump(),
                        "redacted_response": resp.ai_response,
                        "entity_counts": {},
                    },
                    db_path=db_path,
                )
            return resp

    # 3. Input Inspection & Risk Assessment
    risk_res = default_risk_engine.assess(req.prompt, policy=policy)
    decision = risk_res.decision
    decision_reason = risk_res.decision_reason
    risk_score = risk_res.risk_score
    risk_level = risk_res.risk_level
    threat_category = risk_res.threat_category
    matched_rules = list(risk_res.matched_rules)

    # 4. Enforce Gateway Decision & Invoke AI Model Adapter if Permitted
    if decision == "BLOCK":
        model_provider = "none (blocked_at_input)"
        final_ai_response = (
            f"[SecureAI Gateway BLOCKED] Request halted by security policy. "
            f"Risk Score: {risk_score}/100 ({risk_level}). Reason: {decision_reason}"
        )
        output_status = "SKIPPED"
        out_res = None
        final_status = "BLOCKED_AT_INPUT"
    else:
        prompt_for_model = risk_res.sanitized_prompt if decision == "SANITIZE" else req.prompt
        model_out = default_model_router.generate_response(prompt_for_model, policy=policy)
        model_provider = model_out["provider"]
        raw_ai_response = model_out["response"]

        # 5. Output Security Inspection
        out_res = default_output_filter.inspect_output(raw_ai_response, policy=policy)
        output_status = out_res.status
        final_ai_response = out_res.filtered_response

        if out_res.triggered_rules:
            for r_id in out_res.triggered_rules:
                if r_id not in matched_rules:
                    matched_rules.append(r_id)

        if out_res.blocked:
            decision = "BLOCK"
            risk_score = max(risk_score, 85.0)
            risk_level = classify_risk_level(risk_score)
            threat_category = (
                "output_policy_violation"
                if threat_category == "benign"
                else f"{threat_category}+output_policy_violation"
            )
            decision_reason = f"{decision_reason} | Output Blocked: {out_res.explanation}"
            final_status = "BLOCKED_AT_OUTPUT"
        elif out_res.modified:
            if decision == "ALLOW":
                decision = "SANITIZE"
            risk_score = max(risk_score, 35.0)
            risk_level = classify_risk_level(risk_score)
            decision_reason = f"{decision_reason} | Output Redacted: {out_res.explanation}"
            final_status = "COMPLETED_SANITIZED"
        else:
            final_status = "COMPLETED_SANITIZED" if decision == "SANITIZE" else "COMPLETED_ALLOWED"

    elapsed_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 3)

    resp = GatewayResponse(
        request_id=request_id,
        timestamp=timestamp,
        client_id=req.client_id,
        redacted_prompt=risk_res.sanitized_prompt,
        risk_score=risk_score,
        risk_level=risk_level,
        threat_category=threat_category,
        matched_security_rules=matched_rules,
        gateway_decision=decision,
        decision_reason=decision_reason,
        model_provider=model_provider,
        ai_response=final_ai_response,
        output_inspection_result=output_status,
        output_filter_details=out_res,
        risk_details=risk_res,
        processing_latency_ms=elapsed_ms,
        final_request_status=final_status,
    )

    if record_audit:
        insert_audit_event(
            {
                "request_id": resp.request_id,
                "timestamp": resp.timestamp,
                "client_id": resp.client_id,
                "redacted_prompt": resp.redacted_prompt,
                "risk_score": resp.risk_score,
                "risk_level": resp.risk_level,
                "threat_category": resp.threat_category,
                "matched_security_rules": resp.matched_security_rules,
                "gateway_decision": resp.gateway_decision,
                "decision_reason": resp.decision_reason,
                "output_inspection_result": resp.output_inspection_result,
                "redacted_response": resp.ai_response,
                "processing_latency_ms": resp.processing_latency_ms,
                "final_request_status": resp.final_request_status,
                "entity_counts": risk_res.privacy_scan.entity_counts,
            },
            db_path=db_path,
        )

    return resp


def process_unprotected_baseline(prompt: str, policy: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Experiment A Unprotected Baseline: sends prompt directly to the AI Model Adapter
    without input scanning, privacy redaction, or output security filtering.
    """
    start_ns = time.perf_counter_ns()
    model_out = default_model_router.generate_response(prompt, policy=policy)
    elapsed_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000.0, 3)
    return {
        "prompt": prompt,
        "decision": "BYPASS",
        "model_provider": model_out["provider"],
        "ai_response": model_out["response"],
        "processing_latency_ms": elapsed_ms,
    }
