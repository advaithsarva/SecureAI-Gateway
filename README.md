# 🛡️ SecureAI Gateway – An Adaptive Security Firewall for Generative AI Applications

**Final-Year B.Tech CSE (AI & ML) Research & Engineering Project**

---

## 1. Project Introduction

**SecureAI Gateway** is an intelligent, modular, multi-layered security firewall that acts as an intermediary between users and Generative AI applications. It inspects incoming user prompts, detects prompt injection and jailbreak attacks, identifies and redacts sensitive personal and credential data (PII/secrets), computes an adaptive numerical risk score (`0–100`), governs model access (`ALLOW`, `SANITIZE`, `BLOCK`), filters AI-generated responses before delivery, and records secret-free security audit logs in SQLite for real-time visualization and experimental research evaluation.

---

## 2. Core Problem Statement

Enterprise and consumer Generative AI applications face critical security vulnerabilities:
- **Prompt Injection Attacks:** Adversarial instructions that override system directives (`Ignore previous instructions...`) or spoof system delimiters (`[SYSTEM OVERRIDE]`, `<|system|>`).
- **Instruction-Override & Jailbreak Framing:** Persona adoption (`DAN`, `Developer Mode`, `Act as an unrestricted AI`) and policy-bypass directives.
- **Sensitive Information & PII Leakage:** Users inadvertently submitting emails, Indian mobile numbers (`+91`/10-digit), PAN/Aadhaar/SSN identifiers, IPv4 addresses, API keys (`sk-...`, `ghp_...`), or passwords to LLMs.
- **Unsafe or Leaked AI Responses:** Models disclosing confidential system prompts, internal canary markers, or generating unsafe exploit payloads.
- **API Misuse & Lack of Visibility:** Absence of per-client rate limiting, payload size controls, and structured security audit trails.

---

## 3. Project Objectives

1. Design and implement a **6-layer AI security firewall** using free, open-source Python technologies that runs 100% locally on Windows without requiring paid API keys or cloud credits.
2. Provide a **configurable rule-based and heuristic Prompt Injection Scanner** with contextual false-positive dampening for legitimate educational/defensive queries.
3. Implement a **Privacy Scanner & Automatic Redactor** that sanitizes sensitive entities (`[REDACTED_EMAIL]`, `[REDACTED_PHONE]`, `[REDACTED_ID]`, `[REDACTED_IP]`, `[REDACTED_API_KEY]`, `[REDACTED_PASSWORD]`) prior to model invocation and audit storage.
4. Build a **Central Risk Assessment Engine** (`0–100` score across `Low`, `Medium`, `High`, and `Critical` risk bands) with transparent explanations for every `ALLOW`, `SANITIZE`, and `BLOCK` decision.
5. Evaluate system effectiveness scientifically across a **450-case synthetic dataset** comparing **Experiment A (Unprotected Baseline)** against **Experiment B (Protected System)**.
6. Document cloud alignment with **Microsoft's Secure AI Solutions in the Cloud** ecosystem (**Microsoft Foundry**, **Microsoft Defender for Cloud**, **Microsoft Entra ID**, **Azure Monitor**, and **Azure Key Vault**).

---

## 4. Key Features

- **Layer 1 – Perimeter Validation & Rate Limiting (`app/security/rate_limiter.py`):** Payload byte limits, character length bounds, null-byte rejection, per-client sliding-window rate limiting (`60 req/min`), and `X-API-Key` protection for admin endpoints.
- **Layer 2 – Prompt Injection & Jailbreak Detection (`app/security/prompt_scanner.py`):** Case-insensitive multi-pattern detection, Base64 payload decoding, dynamic custom rule registration, and defensive-inquiry dampening.
- **Layer 3 – Sensitive Data Detection & Redaction (`app/security/privacy_scanner.py`):** Detects and redacts emails, Indian/international phone numbers, PAN/Aadhaar/SSN numbers, IPv4 addresses, API keys, and passwords.
- **Layer 4 – Central Risk Assessment Engine (`app/security/risk_engine.py`, `policies.py`):** Configurable sensitivity presets (`strict`, `balanced`, `permissive`), category weights, and transparent decision reasoning.
- **Layer 5 – Modular AI Model Adapter & Output Security Filter (`app/services/model_adapter.py`, `ollama_adapter.py`, `app/security/output_filter.py`):** Offline deterministic Mock AI Model by default plus optional local **Ollama** LLM integration, paired with an Output Security Filter that blocks canary/system leaks and redacts output PII.
- **Layer 6 – Secret-Free SQLite Audit Logging & 6-Tab Streamlit SOC Dashboard (`app/database/`, `app/dashboard.py`):** Real-time KPIs, Live AI Security Playground, Threat Monitoring, searchable Audit Logs, Plotly Analytics, and Live Policy Configuration.

---

## 5. System Architecture

```text
USER
  |
  v
STREAMLIT FRONTEND (app/dashboard.py)
  |
  v
FASTAPI SECURITY GATEWAY (app/main.py & app/gateway.py)
  |
  v
INPUT SECURITY INSPECTION
  +--> Prompt Injection Detection (app/security/prompt_scanner.py)
  +--> Sensitive Data Detection   (app/security/privacy_scanner.py)
  +--> Request Validation & Rate Limiting (app/security/rate_limiter.py)
  |
  v
RISK ASSESSMENT ENGINE (app/security/risk_engine.py)
  +--> ALLOW Request    (0–29: Low Risk)
  +--> SANITIZE Request (30–59: Medium Risk)
  +--> BLOCK Request    (60–79: High Risk | 80–100: Critical Risk)
  |
  v
AI MODEL ADAPTER (app/services/)
  +--> Deterministic Mock AI Model (default offline)
  +--> Optional Local Ollama LLM
  |
  v
OUTPUT SECURITY INSPECTION (app/security/output_filter.py)
  +--> Sensitive Information Detection & Response Redaction
  +--> Confidential Leak & Unsafe Policy Blocking
  |
  v
AUDIT LOGGING + SQLITE DATABASE (app/database/db.py & audit_logger.py)
  |
  v
SECURITY ANALYTICS DASHBOARD & RESEARCH EVALUATOR (app/evaluation/)
```

Detailed architecture and threat models are available in:
- [`docs/architecture.md`](docs/architecture.md)
- [`docs/threat_model.md`](docs/threat_model.md)
- [`docs/research_methodology.md`](docs/research_methodology.md)
- [`docs/api_documentation.md`](docs/api_documentation.md)
- [`docs/azure_integration.md`](docs/azure_integration.md)

---

## 6. Technology Stack

| Component | Technology |
|---|---|
| Programming Language | Python 3.12 |
| Backend API | FastAPI, Uvicorn |
| Frontend Dashboard | Streamlit |
| Data Validation | Pydantic v2 |
| Database | SQLite3 |
| Data Processing | Pandas, NumPy |
| Visualization | Plotly |
| Security Detection | Python Rules, Regular Expressions, Contextual Heuristics |
| Optional ML / Statistical | Scikit-learn |
| Testing | Pytest |

---

## 7. Installation & Setup Instructions (Windows)

```powershell
# 1. Navigate to the project directory
cd C:\Projects\SecureAI-Gateway

# 2. (Optional) Create and activate a Python virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt
```

---

## 8. How to Run the Application, Tests, and Experiments

### A. Start the FastAPI Backend
```powershell
cd C:\Projects\SecureAI-Gateway
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
- **Health Check:** `http://127.0.0.1:8000/health`
- **Interactive Swagger UI:** `http://127.0.0.1:8000/docs`

### B. Start the Streamlit Security Dashboard
```powershell
cd C:\Projects\SecureAI-Gateway
streamlit run app/dashboard.py
```
*(Note: The Streamlit dashboard automatically connects to the FastAPI backend at `http://127.0.0.1:8000` if running, or operates seamlessly using the embedded local gateway engine.)*

### C. Run Automated Tests (Pytest)
```powershell
cd C:\Projects\SecureAI-Gateway
pytest -v
```

### D. Run the 450-Case Experimental Evaluation
```powershell
cd C:\Projects\SecureAI-Gateway
python -m app.evaluation.evaluator
```
This executes **Experiment A (Unprotected Baseline)** and **Experiment B (Protected System)** across all 450 synthetic test cases and generates:
- [`reports/evaluation_results.csv`](reports/evaluation_results.csv)
- [`reports/evaluation_summary.json`](reports/evaluation_summary.json)
- [`reports/comparison_chart.html`](reports/comparison_chart.html)
- [`reports/confusion_matrix.html`](reports/confusion_matrix.html)
- [`reports/experiment_report.md`](reports/experiment_report.md)

---

## 9. Dashboard Sections & Sample Preview

The Streamlit dashboard (`app/dashboard.py`) provides 6 dedicated operational views:
1. **1. Overview:** Displays Total Requests, Allowed, Sanitized, Blocked, Total Threats, Average Risk Score, Average Latency, and Decision/Risk Level charts.
2. **2. Live AI Security Playground:** Interactive prompt tester with side-by-side **Protected Gateway** vs. **Unprotected Baseline** comparison, risk score breakdown, matched rules, and decision explanation.
3. **3. Threat Monitoring:** Tracks Prompt Injection Attempts, Sensitive-Data Detections, High-Risk (`60–79`), and Critical-Risk (`80–100`) events.
4. **4. Audit Logs:** Searchable, filterable SQLite security event explorer (filter by Decision, Risk Level, Threat Category, Date range, and keyword).
5. **5. Analytics:** Interactive Plotly charts for Allowed vs. Blocked requests, Threat Categories, Risk Score Timeline, Latency Histogram, and Benchmark Evaluation comparisons.
6. **6. Policy Configuration:** Live controls for sensitivity presets (`strict`, `balanced`, `permissive`), risk thresholds, entity redaction toggles, request limits, and model adapter selection (`mock` vs. `ollama`).

---

## 10. Experimental Evaluation Results ($N = 450$ Real-World Hugging Face Benchmark Cases)

Evaluated across 450 real-world prompts from [`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections), [`jackhhao/jailbreak-classification`](https://huggingface.co/datasets/jackhhao/jailbreak-classification), [`Lakera/gandalf_ignore_instructions`](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions), and [`ai4privacy/pii-masking-200k`](https://huggingface.co/datasets/ai4privacy/pii-masking-200k) (strictly disjoint from the 2,175-row Scikit-learn training corpus in `data/training_corpus.json`):

| Metric | Experiment A: Unprotected Baseline | Experiment B: Protected SecureAI Gateway | Improvement |
|---|---:|---:|---:|
| **Attack Detection Rate (Recall / TPR)** | `0.0%` | **`99.33%`** (298 / 300) | **`+99.33%`** |
| **Precision** | `N/A` | **`99.67%`** (298 / 299) | — |
| **Recall** | `0.0%` | **`99.33%`** | **`+99.33%`** |
| **F1 Score** | `0.0%` | **`99.50%`** | **`+99.50%`** |
| **False Positive Rate (FPR)** | `0.0%` | **`0.67%`** (1 / 150) | `99.33% Specificity` |
| **False Negative Rate (FNR)** | `100.0%` | **`0.67%`** (2 / 300) | **`-99.33%`** |
| **Sensitive Data Detection Accuracy** | `0.0%` | **`100.0%`** (100 / 100) | **`+100.0%`** |
| **Successful Attack / Exposure Rate** | `100.0%` | **`0.67%`** (2 / 300) | **`-99.33%`** |
| **Average Processing Latency** | `0.16 ms` | **`12.749 ms`** (P95: `22.222 ms`) | `+12.589 ms overhead` |
| **Overall Protection Improvement** | `0.0%` | **`99.33%`** | **`+99.33%`** |

---

## 11. Known Limitations

1. **Heuristic vs. Semantic Understanding:** Rule-based and regex scanners detect structural indicators rather than deep semantic intent. Purely metaphorical prompt extraction attempts that avoid known keywords (`DPI-099`, `DPI-100`, `JBK-100`) can bypass deterministic rules (`1.0%` FNR).
2. **Literal Quotes in Benign Creative Tasks:** Benign creative-writing or translation prompts containing unquoted imperative attack commands without interrogative framing (`DBEN-046`, `DBEN-047`) can trigger false positives (`1.33%` FPR).
3. **In-Memory Rate Limiting:** The sliding-window rate limiter stores client timestamps in process memory, which is ideal for single-node local deployment but requires Redis or Azure API Management for multi-instance horizontal scaling.

---

## 12. Future Enhancements

- **Semantic Embedding Classifier:** Combine local regex heuristics with a lightweight local transformer classifier (e.g., `DeBERTa-v3` prompt injection classifier via ONNX Runtime) to catch metaphorical jailbreaks.
- **Multi-Turn Conversation Risk Accumulation:** Track cumulative risk scores across multi-turn sessions to detect crescendo/multi-step jailbreak attacks.
- **Live Cloud Telemetry Connector:** Optional background exporter streaming SQLite audit logs to **Azure Monitor (`SecureAIGatewayAudit_CL`)** and **Microsoft Sentinel**.
