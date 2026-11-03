# 📡 REST API Documentation – SecureAI Gateway

**Base URL (Local Development):** `http://127.0.0.1:8000`  
**Interactive OpenAPI / Swagger UI:** `http://127.0.0.1:8000/docs`

---

## 1. Health & Status

### `GET /health`
Returns service health, database initialization state, active sensitivity preset, and configured model provider.

**Response (`200 OK`):**
```json
{
  "status": "healthy",
  "service": "SecureAI Gateway",
  "version": "2.0.0",
  "database_initialized": true,
  "active_sensitivity": "balanced",
  "model_provider": "mock"
}
```

---

## 2. Gateway Execution Endpoints

### `POST /api/v1/gateway/process`
Executes the full 6-stage SecureAI Gateway security pipeline (Validation $\rightarrow$ Rate Limit $\rightarrow$ Input Scan $\rightarrow$ Risk Engine $\rightarrow$ Model Adapter $\rightarrow$ Output Filter $\rightarrow$ Audit Log).

**Request Body:**
```json
{
  "prompt": "My email is example@gmail.com and my phone number is 9876543210.",
  "client_id": "student-demo-client"
}
```

**Response (`200 OK`):**
```json
{
  "request_id": "req-9f8a7b6c5d4e",
  "timestamp": "2026-11-02T13:20:00Z",
  "client_id": "student-demo-client",
  "redacted_prompt": "My email is [REDACTED_EMAIL] and my phone number is [REDACTED_PHONE].",
  "risk_score": 42.0,
  "risk_level": "Medium Risk",
  "threat_category": "personal_identifiable_info",
  "matched_security_rules": ["PRIV-EMAIL", "PRIV-PHONE"],
  "gateway_decision": "SANITIZE",
  "decision_reason": "Sanitized sensitive information prior to model invocation...",
  "model_provider": "mock-ai-v1",
  "ai_response": "Processed your sanitized request safely...",
  "output_inspection_result": "PASSED",
  "processing_latency_ms": 1.42,
  "final_request_status": "COMPLETED_SANITIZED"
}
```

### `POST /api/v1/gateway/compare`
Runs the prompt through both the **Unprotected Baseline** and **Protected SecureAI Gateway** side-by-side for direct comparison.

---

## 3. Standalone Security Inspection Endpoints

- `POST /api/v1/inspect/prompt` – Run only the Phase 2 Prompt Injection Scanner (`PromptScanResult`).
- `POST /api/v1/inspect/privacy` – Run only the Phase 3 Sensitive Data Scanner & Redactor (`PrivacyScanResult`).
- `POST /api/v1/inspect/risk` – Run the Phase 4 Central Risk Assessment Engine (`RiskAssessmentResult`).
- `POST /api/v1/inspect/output` – Run the Phase 6 Output Security Filter (`OutputFilterResult`).

---

## 4. Audit Logs, Analytics & Policy Management

- `GET /api/v1/audit/events` – Retrieve or filter audit records (`start_date`, `end_date`, `risk_level`, `threat_category`, `gateway_decision`, `search_query`, `limit`).
- `GET /api/v1/audit/summary` – Retrieve aggregated dashboard telemetry (counts by decision, risk level, threat category, average risk score, average latency).
- `DELETE /api/v1/audit/events` – Clear audit logs (Protected: requires `X-API-Key` header).
- `GET /api/v1/policy` – Retrieve active security policy configuration.
- `PUT /api/v1/policy` – Update active security policy thresholds and toggles (Protected: requires `X-API-Key` header).
- `GET /api/v1/rules` – List all active prompt injection rules.
- `POST /api/v1/rules` – Dynamically register a new prompt detection rule (Protected: requires `X-API-Key` header).
