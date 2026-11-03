"""
FastAPI Backend Application for SecureAI Gateway.
Exposes gateway processing, standalone inspection, audit log queries,
summary statistics, policy management, and experimental evaluation endpoints.
"""
from contextlib import asynccontextmanager
from typing import Optional, Dict, Any

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.config import ADMIN_API_TOKEN
from app.database.audit_logger import (
    clear_audit_events,
    filter_events,
    get_recent_events,
    get_summary_statistics,
)
from app.database.db import init_database, load_active_policy, save_active_policy
from app.gateway import GatewayRequest, GatewayResponse, process_gateway_request, process_unprotected_baseline
from app.security.output_filter import default_output_filter
from app.security.policies import SecurityPolicyConfig, apply_sensitivity_preset
from app.security.privacy_scanner import default_privacy_scanner
from app.security.prompt_scanner import default_prompt_scanner
from app.security.rate_limiter import verify_admin_api_key
from app.security.risk_engine import default_risk_engine


class CustomRulePayload(BaseModel):
    rule_id: str
    name: str
    category: str
    severity: str
    weight: float
    pattern: str
    explanation: str


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_database()
    yield


app = FastAPI(
    title="SecureAI Gateway",
    description="An Adaptive Security Firewall for Generative AI Applications",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_endpoint() -> Dict[str, Any]:
    init_database()
    policy = load_active_policy()
    return {
        "status": "healthy",
        "service": "SecureAI Gateway",
        "version": "2.0.0",
        "database_initialized": True,
        "active_sensitivity": policy.get("sensitivity", "balanced"),
        "model_provider": policy.get("model_provider", "mock"),
    }


@app.post("/api/v1/gateway/process", response_model=GatewayResponse)
def gateway_process_endpoint(req: GatewayRequest) -> GatewayResponse:
    resp = process_gateway_request(req)
    return resp


@app.post("/api/v1/gateway/compare")
def gateway_compare_endpoint(req: GatewayRequest) -> Dict[str, Any]:
    policy = load_active_policy()
    if req.policy_override:
        policy.update(req.policy_override)
    unprotected = process_unprotected_baseline(req.prompt, policy=policy)
    protected = process_gateway_request(req)
    return {
        "unprotected_baseline": unprotected,
        "protected_gateway": protected.model_dump(),
    }


@app.post("/api/v1/inspect/prompt")
def inspect_prompt_endpoint(req: GatewayRequest):
    return default_prompt_scanner.scan(req.prompt)


@app.post("/api/v1/inspect/privacy")
def inspect_privacy_endpoint(req: GatewayRequest):
    policy = load_active_policy()
    return default_privacy_scanner.scan_and_redact(req.prompt, policy=policy)


@app.post("/api/v1/inspect/risk")
def inspect_risk_endpoint(req: GatewayRequest):
    policy = load_active_policy()
    if req.policy_override:
        policy.update(req.policy_override)
    return default_risk_engine.assess(req.prompt, policy=policy)


@app.post("/api/v1/inspect/output")
def inspect_output_endpoint(req: GatewayRequest):
    policy = load_active_policy()
    return default_output_filter.inspect_output(req.prompt, policy=policy)


@app.get("/api/v1/rules")
def list_security_rules_endpoint():
    return {"prompt_rules": default_prompt_scanner.list_rules()}


@app.post("/api/v1/rules")
def register_custom_rule_endpoint(
    payload: CustomRulePayload,
    x_api_key: Optional[str] = Header(default=ADMIN_API_TOKEN),
):
    if not verify_admin_api_key(x_api_key):
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header.")
    default_prompt_scanner.register_rule(
        rule_id=payload.rule_id,
        name=payload.name,
        category=payload.category,
        severity=payload.severity,
        weight=payload.weight,
        pattern=payload.pattern,
        explanation=payload.explanation,
    )
    return {"status": "registered", "rule_id": payload.rule_id}


@app.get("/api/v1/audit/events")
def query_audit_events_endpoint(
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    threat_category: Optional[str] = Query(None),
    gateway_decision: Optional[str] = Query(None),
    search_query: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
):
    if any([start_date, end_date, risk_level, threat_category, gateway_decision, search_query]):
        events = filter_events(
            start_date=start_date,
            end_date=end_date,
            risk_level=risk_level,
            threat_category=threat_category,
            gateway_decision=gateway_decision,
            search_query=search_query,
            limit=limit,
        )
    else:
        events = get_recent_events(limit=limit)
    return {"events": events, "count": len(events)}


@app.delete("/api/v1/audit/events")
def delete_audit_events_endpoint(
    x_api_key: Optional[str] = Header(default=ADMIN_API_TOKEN),
):
    if not verify_admin_api_key(x_api_key):
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header.")
    clear_audit_events()
    return {"status": "cleared"}


@app.get("/api/v1/audit/summary")
def summary_statistics_endpoint():
    return get_summary_statistics()


@app.get("/api/v1/policy")
def get_policy_endpoint():
    return load_active_policy()


@app.put("/api/v1/policy")
def update_policy_endpoint(
    cfg: SecurityPolicyConfig,
    apply_preset: Optional[str] = Query(None, description="Optional preset: strict, balanced, permissive"),
    x_api_key: Optional[str] = Header(default=ADMIN_API_TOKEN),
):
    if not verify_admin_api_key(x_api_key):
        raise HTTPException(status_code=401, detail="Invalid or missing X-API-Key header.")
    updated = apply_sensitivity_preset(cfg.model_dump(), preset_name=apply_preset)
    return save_active_policy(updated)
