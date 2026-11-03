# 🏗️ System Architecture – SecureAI Gateway

## 1. Architectural Overview

**SecureAI Gateway** is an adaptive, multi-layered security firewall positioned between user interfaces and Generative AI models. Rather than relying on a single prompt filter or trusting the underlying LLM to enforce its own system prompt boundaries, SecureAI Gateway enforces defense-in-depth across the entire request-response lifecycle.

```mermaid
flowchart TD
    User(["User / Client Application"]) --> Frontend["Streamlit Security Dashboard\n(app/dashboard.py)"]
    User --> FastAPI["FastAPI Security Gateway\n(app/main.py & app/gateway.py)"]
    Frontend --> FastAPI

    subgraph Layer1["Layer 1: Perimeter Validation & Rate Control"]
        FastAPI --> ReqVal["Request Size & Length Validation\n(app/security/rate_limiter.py)"]
        ReqVal --> RateLim["Sliding-Window Client Rate Limiter\n(60 req/min default)"]
    end

    subgraph Layer2["Layer 2: Input Security Inspection"]
        RateLim --> PromptScan["Prompt Injection & Jailbreak Scanner\n(app/security/prompt_scanner.py)"]
        RateLim --> PrivScan["Sensitive Data (PII & Secret) Scanner\n(app/security/privacy_scanner.py)"]
    end

    subgraph Layer3["Layer 3: Central Risk Assessment Engine"]
        PromptScan --> RiskEngine["Risk Scoring (0-100) & Policy Engine\n(app/security/risk_engine.py & policies.py)"]
        PrivScan --> RiskEngine
        RiskEngine --> Decision{"Gateway Decision"}
    end

    Decision -- "ALLOW (0-29 Low Risk)" --> ModelRouter["AI Model Adapter Router\n(app/services/model_adapter.py)"]
    Decision -- "SANITIZE (30-59 Medium Risk)" --> Sanitize["Replace PII/Secrets with\n[REDACTED_*] Placeholders"]
    Sanitize --> ModelRouter
    Decision -- "BLOCK (60-100 High/Critical Risk)" --> BlockOut["Return Security Policy Block Notice"]

    subgraph Layer4["Layer 4: Modular AI Model Execution"]
        ModelRouter --> MockModel["Deterministic Mock AI Model\n(Default Offline Adapter)"]
        ModelRouter -. "Optional Local LLM" .-> OllamaModel["Ollama Local Runtime\n(app/services/ollama_adapter.py)"]
    end

    subgraph Layer5["Layer 5: Output Security Inspection"]
        MockModel --> OutFilter["Output Security Filter\n(app/security/output_filter.py)"]
        OllamaModel -.-> OutFilter
        OutFilter --> OutDecision{"Output Policy Check"}
        OutDecision -- "PASSED / REDACTED" --> FinalResp["Deliver Safe Response to User"]
        OutDecision -- "BLOCKED (Canary / Leak)" --> BlockOut
    end

    subgraph Layer6["Layer 6: Secret-Free Audit Logging & Analytics"]
        FinalResp --> AuditLog["Audit Logger\n(app/database/audit_logger.py)"]
        BlockOut --> AuditLog
        AuditLog --> SQLite[("SQLite Database\n(data/secureai_audit.db)")]
        SQLite --> Analytics["Real-Time Analytics & Experimental Evaluator\n(app/evaluation/evaluator.py)"]
    end
```

---

## 2. Component Responsibilities

| Module | File Path | Core Responsibility |
|---|---|---|
| **FastAPI Server** | `app/main.py` | Exposes REST endpoints for gateway execution, standalone scanners, audit log queries, policy updates, and health checks. |
| **Gateway Orchestrator** | `app/gateway.py` | Coordinates the 6-layer pipeline (`process_gateway_request`) and provides the unprotected baseline runner (`process_unprotected_baseline`) for experimental comparison. |
| **Prompt Injection Scanner** | `app/security/prompt_scanner.py` | Configurable regex and heuristic rule engine with dynamic rule registration, Base64 obfuscation decoding, and defensive/educational context dampening. |
| **Privacy Scanner** | `app/security/privacy_scanner.py` | Detects and redacts emails, Indian/international phone numbers, PAN/Aadhaar/SSN identifiers, IPv4 addresses, API keys, and passwords. |
| **Risk Assessment Engine** | `app/security/risk_engine.py` | Combines weighted scanner outputs into a 0–100 risk score (`Low Risk`, `Medium Risk`, `High Risk`, `Critical Risk`) and determines `ALLOW`, `SANITIZE`, or `BLOCK`. |
| **Output Security Filter** | `app/security/output_filter.py` | Scans model outputs for leaked system instructions, synthetic canary markers, residual PII, and unsafe exploit payloads. |
| **Rate Limiter & Validator** | `app/security/rate_limiter.py` | Enforces payload byte limits, character length bounds, null-byte checks, sliding-window rate limits, and `X-API-Key` authentication. |
| **AI Model Adapters** | `app/services/model_adapter.py`, `ollama_adapter.py` | Provides an offline deterministic Mock AI Model alongside an optional local Ollama LLM connector. |
| **Audit Logger & DB** | `app/database/db.py`, `audit_logger.py` | Persists redacted security events and active policy state in SQLite; supports date/risk/category filtering and summary statistics. |
| **Evaluation Engine** | `app/evaluation/attack_dataset.py`, `evaluator.py`, `metrics.py` | Generates 450 synthetic test cases and runs Experiment A (Unprotected) vs. Experiment B (Protected), producing CSV, JSON, HTML charts, and Markdown reports. |
| **Streamlit Dashboard** | `app/dashboard.py` | Interactive 6-section Security Operations Center dashboard connected to live gateway and SQLite data. |
