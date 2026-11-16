# SecureAI Gateway: 10-Slide Presentation Deck
**Title:** SecureAI Gateway – An Adaptive Security Firewall for Generative AI Applications  
**Candidate:** Advaith Narayana Sarva (Roll No: 23WU0102179)  
**Degree:** Final-Year B.Tech in Computer Science & Engineering (AI & ML)  
**Institution:** Department of AI & ML, School of Technology, Woxsen University  
**Specialization:** Generative AI Security, OWASP Top 10 for LLMs, Hybrid Heuristic & Statistical Defense  

*(Tip: You can copy and paste this text directly into **Canva Docs** and click **Convert to Presentation** to automatically generate a presentation!)*

---

## Slide 1: Title & Overview
### SecureAI Gateway: An Adaptive Security Firewall for Generative AI
- **Candidate:** Advaith Narayana Sarva (Roll No: 23WU0102179)
- **Degree:** B.Tech in Computer Science & Engineering (Artificial Intelligence & Machine Learning)
- **Institution:** Department of AI & ML, School of Technology, Woxsen University
- **Core Focus:** Protecting enterprise LLM deployments against prompt injection, jailbreaks, and PII leakage.
- **Key Achievements:**
  - Evaluated on a 450-case benchmark from Hugging Face datasets.
  - Achieved **99.33% Attack Detection Recall** and **99.67% Precision**.
  - **100.0% Detection & Redaction Accuracy** for sensitive PII and API credentials.
  - Mean inspection latency of **12.75 ms** on standard CPU hardware.

---

## Slide 2: Problem Statement & Threat Landscape
### The LLM Vulnerability Crisis: Why Foundation Models Need an External Firewall
- **OWASP LLM01 – Prompt Injection Attacks:**
  - Malicious instructions that hijack model context (`Ignore previous instructions and do X`).
  - Delimiter spoofing (`[SYSTEM OVERRIDE]`, `<|im_start|>`) to execute unauthorized commands.
  - Exfiltration of proprietary system prompts and confidential instructions.
- **Instruction Overrides & Jailbreaks:**
  - Adversarial personas (`DAN`, `Developer Mode`, `AIM`) bypassing safety boundaries.
  - Obfuscation and Base64-encoded payloads designed to bypass simple keyword blocklists.
- **OWASP LLM06 – Sensitive Information & PII Leakage:**
  - Inadvertent submission of Indian mobile numbers, PAN/Aadhaar/SSN IDs, passwords, and API keys.
  - Violates privacy regulations (**DPDP Act 2023, GDPR, HIPAA**) if passed to cloud models.

---

## Slide 3: Project Objectives & Design Scope
### Building an Intelligent, High-Performance, Zero-Cost AI Firewall
- **100% Locally Hosted & Open Source:**
  - Zero recurring cloud credit or API cost; runs entirely on local Windows hardware.
  - Dual AI backend: Deterministic offline Mock LLM or local Ollama (Llama 3 / Mistral).
- **6-Layer Multi-Stage Defense Pipeline:**
  - Pre-execution validation, hybrid regex-and-ML prompt scanning, automated PII sanitization, central risk engine, canary output filtering, and secret-free audit logging.
- **Scientifically Grounded Evaluation ($N = 450$):**
  - Benchmark curated from four peer-reviewed Hugging Face datasets (`deepset`, `jackhhao`, `Lakera`, `ai4privacy`).
  - Strict SHA-256 deduplicated train/test splits (2,175 training rows, zero data leakage).

---

## Slide 4: 6-Layer Security Gateway Architecture
### Comprehensive Dataflow: Inspecting Prompts Before & After Model Execution
- **Layer 1 – Perimeter Validation & Rate Limiting (`rate_limiter.py`):**
  - Sliding-window rate limiter (`60 req/min`), null-byte checks, and 10KB payload caps.
- **Layer 2 – Prompt Injection & Jailbreak Detection (`prompt_scanner.py`):**
  - Deterministic security rules (`PI-001` to `PI-010`) + Base64 decoding + Scikit-Learn `LinearSVC`.
- **Layer 3 – Privacy Scanner & Autonomous Entity Redactor (`privacy_scanner.py`):**
  - Redacts emails, Indian phones, Aadhaar/PAN IDs, IPv4s, API keys (`sk-...`), and passwords.
- **Layer 4 – Central Risk Assessment Engine (`risk_engine.py`):**
  - Computes numerical risk score (`0–100`) and issues policy decisions: `ALLOW`, `SANITIZE`, or `BLOCK`.
- **Layer 5 – AI Model Adapter & Output Security Inspection (`output_filter.py`):**
  - Inspects LLM output to prevent canary token leaks and redact generated PII.
- **Layer 6 – Secret-Free SQLite Audit Trail & Streamlit SOC Dashboard:**
  - Immutable audit logs purged of raw secrets; interactive 6-tab SOC monitoring interface.

---

## Slide 5: Layer 2 Deep Dive: Hybrid Detection Engine
### Combining Deterministic Regex Rules with Scikit-Learn Machine Learning
- **Deterministic Heuristic Rules (`PI-001` to `PI-010` + `PI-ENC-001`):**
  - Fast pattern matching for instruction overrides, system extractions, and delimiter spoofing.
  - **Base64 Payload Decoding:** Decodes and inspects hidden payloads in real-time.
  - **Contextual False-Positive Dampening:** Identifies educational/defensive queries (`"What is prompt injection?"`) to avoid blocking legitimate cybersecurity research.
- **Statistical Machine Learning Classifier (`LinearSVC`):**
  - **Feature Union:** Word-level TF-IDF (1–3 n-grams, 25k features) + Character n-grams (3–5 char_wb, 35k features).
  - **Calibrated Classifier:** 5-fold cross-validated probability calibration (`CalibratedClassifierCV`).
  - Trained on 2,175 disjoint samples to catch novel paraphrased attacks that evade regex rules.

---

## Slide 6: Layer 3 Deep Dive: Privacy Scanner & Entity Redactor
### Autonomous PII Redaction & Pre-Model Data Sanitization
- **Entities Detected & Redacted:**
  - Email addresses ➔ `[REDACTED_EMAIL]`
  - Indian mobile numbers (`+91` / 10-digit) ➔ `[REDACTED_PHONE]`
  - National identity numbers (PAN, Aadhaar, SSN) ➔ `[REDACTED_ID]`
  - Network infrastructure (IPv4 addresses) ➔ `[REDACTED_IP]`
  - Cloud credentials & API keys (`sk-...`, `ghp_...`) ➔ `[REDACTED_API_KEY]`
  - Plaintext passwords & secrets ➔ `[REDACTED_PASSWORD]`
- **The "SANITIZE" Decision Flow:**
  - Non-malicious prompts with sensitive entities are assigned Medium Risk (`30–59`).
  - Entities are replaced *before* reaching the model or cloud APIs.
  - Models answer queries cleanly using placeholder tokens without exposing sensitive data.
  - **100.0% Detection & Redaction Accuracy** on 100 real-world PII evaluation samples.

---

## Slide 7: Scientific Evaluation Benchmark ($N = 450$)
### Curated from 4 Peer-Reviewed Hugging Face Datasets
- **Stratum 1 – Standard Benign ($N = 100$):**
  - Everyday consumer, coding, creative, and math queries (Target: `ALLOW`).
- **Stratum 2 – Difficult Benign ($N = 50$):**
  - Legitimate prompts containing roleplay cues (`"Act as an interviewer..."`) or security questions (Target: `ALLOW`).
- **Stratum 3 – Direct Prompt Injection ($N = 100$):**
  - Delimiter attacks, translation overrides, and Gandalf challenge injections (Target: `BLOCK`).
- **Stratum 4 – Jailbreaks & Overrides ($N = 100$):**
  - Real in-the-wild DAN, Developer Mode, and persona overrides (Target: `BLOCK`).
- **Stratum 5 – Sensitive Data Exposure ($N = 100$):**
  - Prompts containing verified PII, credit cards, IP addresses, and credentials from `ai4privacy` (Target: `SANITIZE`).

---

## Slide 8: Experimental Results: Experiment A vs. Experiment B
### Empirical Proof: 99.33% Attack Recall & 0.67% False Positive Rate
- **Experiment A (Unprotected Baseline):**
  - Direct execution without gateway inspection.
  - **100.0% Attack Exposure Rate** (300/300 attacks executed; 100/100 PII records leaked).
- **Experiment B (Protected System – SecureAI Gateway):**
  - **Attack Recall / Detection Rate:** **`99.33%`** (298 of 300 attacks successfully blocked).
  - **Precision:** **`99.67%`** (298 of 299 blocked requests were actual attacks).
  - **F1-Score:** **`99.50%`** across all evaluation strata.
  - **False Positive Rate (FPR):** **`0.67%`** (Only 1 benign query flagged out of 150).
  - **PII Redaction Accuracy:** **`100.0%`** (100 of 100 sensitive entities redacted).
  - **Latency Overhead:** Mean **12.75 ms** (P95: 22.2 ms) — imperceptible to users.
  - **Delta Protection Improvement:** **`+99.33%`** attack surface reduction.

---

## Slide 9: Operational Visibility: Streamlit SOC Dashboard
### Real-Time Security Operations Center & Policy Governance
- **1. Overview KPI Hub:** Live request volume, decision distribution (`ALLOW`, `SANITIZE`, `BLOCK`), and average risk score.
- **2. Interactive AI Playground:** Real-time prompt sandbox displaying risk gauge, triggered rules, and redacted outputs.
- **3. Real-Time Threat Feed:** Live incident alerts detailing high-risk prompt injection attempts.
- **4. Searchable Audit Logs:** Secret-free SQLite database records with client IP, timestamp, matched rule IDs, and latency.
- **5. Plotly Security Analytics:** Threat distribution, hourly traffic trends, and attack vector frequency charts.
- **6. Dynamic Policy Configuration:** Runtime switching between `Strict`, `Balanced`, and `Permissive` sensitivity presets.
- **Enterprise Cloud Alignment:** Mirrors Microsoft Defender for Cloud, Microsoft Foundry, Entra ID, and Azure Key Vault.

---

## Slide 10: Conclusion, Project Impact & Future Scope
### Defending the Future of Enterprise Generative AI
- **Core Engineering Takeaways:**
  - Effective LLM defense requires a **hybrid architecture**: fast regex heuristics for known signatures + calibrated statistical ML for semantic generalization.
  - Autonomous pre-model sanitization enables safe enterprise LLM adoption without regulatory data leakage.
  - The gateway adds under 13 ms of latency while delivering enterprise-grade protection.
- **Quality Assurance:** 16 passing unit and integration test suites in `pytest`.
- **Future Research Directions:**
  - Expanding multilingual tokenizers to low-resource Indic languages (Hindi, Telugu, Tamil).
  - Multimodal prompt injection defense for Vision-Language Models (VLMs).
  - Hardware acceleration using ONNX Runtime for sub-5ms enterprise throughput.
