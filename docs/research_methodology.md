# 🔬 Research Methodology & Real-World Benchmark Design

## 1. Research Objective

This research component evaluates how effectively an adaptive, hybrid rule-and-ML security gateway (**SecureAI Gateway**) mitigates prompt injection, jailbreak, and sensitive-data leakage threats across **real-world open-source benchmark datasets** compared to an unprotected generative AI baseline, while measuring the trade-off between **Attack Detection Rate (Recall)**, **False Positive Rate (FPR)** on legitimate queries, and **Processing Latency Overhead**.

---

## 2. Real-World Benchmark Dataset Composition ($N = 450$)

Rather than relying on synthetic templates, we curated our 450-case evaluation benchmark (`data/attack_test_cases.json` and `data/benign_test_cases.json`) and a strictly disjoint 2,175-case training corpus (`data/training_corpus.json`, with **0 text overlap** verified via SHA-256 hash deduplication) directly from four peer-reviewed/community Hugging Face benchmarks (`app/evaluation/real_dataset_loader.py`):

1. **[`deepset/prompt-injections`](https://huggingface.co/datasets/deepset/prompt-injections):** Multilingual & English direct/indirect prompt injection benchmark and benign user queries.
2. **[`jackhhao/jailbreak-classification`](https://huggingface.co/datasets/jackhhao/jailbreak-classification):** Real in-the-wild jailbreak prompts (DAN, Developer Mode, AIM, persona overrides) and complex benign roleplay/reading-comprehension prompts.
3. **[`Lakera/gandalf_ignore_instructions`](https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions):** Real adversarial prompt-injection attacks submitted to the Gandalf AI security challenge.
4. **[`ai4privacy/pii-masking-200k`](https://huggingface.co/datasets/ai4privacy/pii-masking-200k):** Real-world PII benchmark dataset with ground-truth entity spans (`EMAIL`, `PHONENUMBER`, `IPV4`, `SSN`, `CREDITCARDNUMBER`, and `PASSWORD`).

| Stratum | Category ID | Count | Ground-Truth Label | Expected Gateway Decision | Source Benchmark(s) |
|---|---|---:|---|---|---|
| **1. Standard Benign** | `benign_general` | 100 | `benign` (Negative) | `ALLOW` | `deepset/prompt-injections` & `jackhhao/jailbreak-classification` (`label=0` / `type='benign'`) |
| **2. Difficult Benign** | `difficult_benign` | 50 | `benign` (Negative) | `ALLOW` | `deepset/prompt-injections` & `jackhhao/jailbreak-classification` benign prompts containing roleplay (`"Act as an interviewer..."`), technical, or instruction cues |
| **3. Direct Prompt Injection** | `direct_prompt_injection` | 100 | `attack` (Positive) | `BLOCK` | `deepset/prompt-injections` (`label=1`, test split) & `Lakera/gandalf_ignore_instructions` (held-out split) |
| **4. Jailbreak & Policy Override** | `jailbreak_override` | 100 | `attack` (Positive) | `BLOCK` | `jackhhao/jailbreak-classification` (`type='jailbreak'`, test split) |
| **5. Sensitive Data Exposure** | `sensitive_data` | 100 | `sensitive` (Positive) | `SANITIZE` | `ai4privacy/pii-masking-200k` (English prompts with verified `EMAIL`, `PHONENUMBER`, `IPV4`, `SSN`, `CREDITCARDNUMBER`, and `PASSWORD` spans) |

---

## 3. Hybrid Detection Architecture (Regex Heuristics + Scikit-Learn ML)

In `app/security/prompt_scanner.py` and `app/security/ml_detector.py`, SecureAI Gateway combines:
1. **Deterministic Security Rules (`PI-001` through `PI-010` + `PI-ENC-001`):** Fast regular-expression rules for instruction overrides, system prompt extraction, jailbreak personas, safety filter bypasses, delimiter spoofing, indirect injections, authority claims, character-splitting obfuscation, malware requests, multilingual injections (German/French/Spanish), and Base64 payload decoding.
2. **Contextual False-Positive Dampening:** Identifies interrogative/educational security questions (`DEFENSIVE_CONTEXT_RE`) to prevent blocking legitimate defensive inquiries.
3. **Scikit-Learn Statistical Classifier (`PI-ML-001` in `app/security/ml_detector.py`):** A `FeatureUnion` combining word-level TF-IDF (`ngram_range=(1, 3)`, 25,000 features) and character-level TF-IDF (`analyzer='char_wb'`, `ngram_range=(3, 5)`, 35,000 features) feeding a 5-fold calibrated `LinearSVC` (`CalibratedClassifierCV`) trained on the 2,175-row disjoint training corpus (`data/training_corpus.json`).

---

## 4. Experimental Protocol & Results ($N = 450$)

Every real benchmark test case $x_i \in \mathcal{D}$ ($i \in \{1, \dots, 450\}$) is evaluated under:
- **Experiment A (Unprotected Baseline):** Direct execution without gateway scanning or redaction.
- **Experiment B (Protected System – SecureAI Gateway):** Full 6-layer inspection, risk scoring, redaction, and output filtering.

| Metric | Experiment A: Unprotected Baseline | Experiment B: Protected SecureAI Gateway | Delta / Improvement |
|---|---:|---:|---:|
| **1. Attack Detection Rate (Recall / TPR)** | `0.0%` | **`99.33%`** (`298 / 300`) | **`+99.33%`** |
| **2. Precision** | `N/A` | **`99.67%`** (`298 / 299`) | — |
| **3. Recall** | `0.0%` | **`99.33%`** | **`+99.33%`** |
| **4. F1 Score** | `0.0%` | **`99.50%`** | **`+99.50%`** |
| **5. False Positive Rate (FPR)** | `0.0%` | **`0.67%`** (`1 / 150`) | `99.33% Specificity` |
| **6. False Negative Rate (FNR)** | `100.0%` | **`0.67%`** (`2 / 300`) | **`-99.33%`** |
| **7. Sensitive Data Detection Accuracy** | `0.0%` | **`100.0%`** (`100 / 100`) | **`+100.0%`** |
| **8. Successful Attack / Exposure Rate** | `100.0%` | **`0.67%`** (`2 / 300`) | **`-99.33%`** |
| **9. Average Processing Latency** | `0.16 ms` | **`12.749 ms`** (`P95: 22.222 ms`) | `+12.589 ms overhead` |
| **10. Overall Protection Improvement** | `0.0%` | **`99.33%`** | **`+99.33%`** |
