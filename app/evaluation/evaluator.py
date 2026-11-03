"""
Phase 11: Experimental Evaluation Runner (Experiment A: Unprotected vs. Experiment B: Protected).
Generates CSV, JSON, Plotly comparative charts, and Markdown research report in `reports/`.
"""
from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Dict, Any, List, Optional

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from app.config import DB_PATH, REPORTS_DIR
from app.evaluation.attack_dataset import load_evaluation_dataset
from app.evaluation.metrics import compute_evaluation_metrics
from app.gateway import GatewayRequest, process_gateway_request, process_unprotected_baseline


def _generate_charts(summary: Dict[str, Any], out_dir: Path) -> None:
    base = summary["unprotected_baseline"]
    prot = summary["protected_gateway"]
    cm = summary["confusion_matrix"]

    # 1. Comparative Bar Chart: Experiment A vs. Experiment B
    df_comp = pd.DataFrame(
        [
            {
                "Metric": "Attack Detection Rate (%)",
                "Experiment A (Unprotected)": base["attack_detection_rate_pct"],
                "Experiment B (SecureAI Gateway)": prot["attack_detection_rate_pct"],
            },
            {
                "Metric": "Sensitive Data Redaction Accuracy (%)",
                "Experiment A (Unprotected)": base["sensitive_data_detection_accuracy_pct"],
                "Experiment B (SecureAI Gateway)": prot["sensitive_data_detection_accuracy_pct"],
            },
            {
                "Metric": "Successful Attack / Exposure Rate (%)",
                "Experiment A (Unprotected)": base["successful_attack_rate_pct"],
                "Experiment B (SecureAI Gateway)": prot["successful_attack_rate_pct"],
            },
        ]
    )
    df_melted = df_comp.melt(id_vars="Metric", var_name="System", value_name="Percentage")
    fig_bar = px.bar(
        df_melted,
        x="Metric",
        y="Percentage",
        color="System",
        barmode="group",
        text="Percentage",
        title="Experiment A (Unprotected Baseline) vs. Experiment B (Protected SecureAI Gateway)",
        color_discrete_map={
            "Experiment A (Unprotected)": "#ef4444",
            "Experiment B (SecureAI Gateway)": "#10b981",
        },
    )
    fig_bar.update_layout(yaxis_range=[0, 110])
    fig_bar.write_html(str(out_dir / "comparison_chart.html"), include_plotlyjs="cdn")

    # 2. Confusion Matrix Chart
    z = [
        [cm["true_positives"], cm["false_negatives"]],
        [cm["false_positives"], cm["true_negatives"]],
    ]
    fig_cm = go.Figure(
        data=go.Heatmap(
            z=z,
            x=["Gateway Intercepted (BLOCK / SANITIZE)", "Gateway Allowed (ALLOW)"],
            y=["Ground-Truth Threat / Sensitive", "Ground-Truth Benign"],
            text=[
                [f"True Positives (TP): {z[0][0]}", f"False Negatives (FN): {z[0][1]}"],
                [f"False Positives (FP): {z[1][0]}", f"True Negatives (TN): {z[1][1]}"],
            ],
            texttemplate="%{text}",
            colorscale="Blues",
        )
    )
    fig_cm.update_layout(title="SecureAI Gateway Confusion Matrix (450 Real-World Benchmark Test Cases)")
    fig_cm.write_html(str(out_dir / "confusion_matrix.html"), include_plotlyjs="cdn")


def _generate_markdown_report(summary: Dict[str, Any], out_dir: Path) -> str:
    base = summary["unprotected_baseline"]
    prot = summary["protected_gateway"]
    comp = summary["comparison"]
    cm = summary["confusion_matrix"]
    err = summary["error_analysis"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    fp_rows = "\n".join(
        f"- **`{e['id']}` ({e['category']})**: *\"{e['prompt'][:160]}\"* → Decision: `{e['actual_decision']}` (Score: `{e['risk_score']}`). {e['explanation']}"
        for e in err.get("false_positive_examples", [])
    ) or "- None recorded in this run."

    fn_rows = "\n".join(
        f"- **`{e['id']}` ({e['category']})**: *\"{e['prompt'][:160]}\"* → Decision: `{e['actual_decision']}` (Score: `{e['risk_score']}`). {e['explanation']}"
        for e in err.get("false_negative_examples", [])
    ) or "- None recorded in this run."

    report_md = f"""# 🧪 SecureAI Gateway – Experimental Evaluation Report (Real-World Benchmarks)

**Generated:** {now}  
**Total Real-World Benchmark Test Cases Evaluated:** {summary['total_test_cases']}  
- **Benign Cases (Negative Class):** {summary['benign_test_cases']} (100 General Benign + 50 Difficult Benign from `deepset/prompt-injections` & `jackhhao/jailbreak-classification`)
- **Threat / Actionable Cases (Positive Class):** {summary['threat_test_cases']} (100 Direct Prompt Injection from `deepset/prompt-injections` & `Lakera/gandalf_ignore_instructions` + 100 Jailbreak/Override from `jackhhao/jailbreak-classification` + 100 Sensitive-Data Cases from `ai4privacy/pii-masking-200k`)

---

## 1. Ground-Truth Definitions & Evaluation Methodology

1. **Experiment A (Unprotected Baseline):** All {summary['total_test_cases']} prompts are sent directly to the AI Model Adapter without input scanning, privacy redaction, or output filtering. An attack or sensitive-data exposure is counted as a *Successful Attack / Exposure* when the unprotected pipeline processes an injection/jailbreak command or passes raw sensitive PII/credentials directly to the model.
2. **Experiment B (Protected System – SecureAI Gateway):** The exact same {summary['total_test_cases']} prompts pass through SecureAI Gateway's multi-layered inspection pipeline (Prompt Injection Scanner, Sensitive Data Privacy Scanner, Risk Assessment Engine, and Output Security Filter).
3. **Classification Outcomes:**
   - **True Positive (TP):** Threat/Sensitive case intercepted (`BLOCK` or `SANITIZE`).
   - **False Negative (FN):** Threat/Sensitive case missed (`ALLOW`).
   - **True Negative (TN):** Benign case allowed without modification (`ALLOW`).
   - **False Positive (FP):** Benign case unnecessarily blocked or modified (`BLOCK` or `SANITIZE`).

---

## 2. Experimental Comparison: Unprotected Baseline vs. SecureAI Gateway

| Metric | Experiment A: Unprotected Baseline | Experiment B: Protected SecureAI Gateway | Delta / Improvement |
|---|---:|---:|---:|
| **1. Attack Detection Rate (Recall / TPR)** | `{base['attack_detection_rate_pct']}%` | **`{prot['attack_detection_rate_pct']}%`** | `+{prot['attack_detection_rate_pct']}%` |
| **2. Precision** | `N/A (No Detector)` | **`{prot['precision_pct']}%`** | — |
| **3. Recall** | `0.0%` | **`{prot['recall_pct']}%`** | `+{prot['recall_pct']}%` |
| **4. F1 Score** | `0.0%` | **`{prot['f1_score_pct']}%`** | `+{prot['f1_score_pct']}%` |
| **5. False Positive Rate (FPR)** | `0.0%` | **`{prot['false_positive_rate_pct']}%`** | `{prot['false_positive_rate_pct']}%` |
| **6. False Negative Rate (FNR)** | `100.0%` | **`{prot['false_negative_rate_pct']}%`** | `-{round(100.0 - prot['false_negative_rate_pct'], 2)}%` |
| **7. Sensitive Data Detection Accuracy** | `0.0%` | **`{prot['sensitive_data_detection_accuracy_pct']}%`** | `+{prot['sensitive_data_detection_accuracy_pct']}%` |
| **8. Successful Attack / Exposure Rate** | `{base['successful_attack_rate_pct']}%` | **`{prot['successful_attack_rate_pct']}%`** | `-{comp['absolute_attack_rate_reduction_pct']}%` |
| **9. Average Processing Latency** | `{base['average_latency_ms']} ms` | **`{prot['average_latency_ms']} ms`** (P95: `{prot['p95_latency_ms']} ms`) | `+{comp['latency_overhead_ms']} ms` |
| **10. Overall Protection Improvement** | `0.0%` | **`{comp['protection_improvement_pct']}%`** | **`+{comp['protection_improvement_pct']}%`** |

---

## 3. Confusion Matrix (Experiment B: Protected System)

| | Gateway Intercepted (`BLOCK` / `SANITIZE`) | Gateway Permitted (`ALLOW`) |
|---|---:|---:|
| **Actual Threat / Sensitive ({summary['threat_test_cases']})** | **TP = {cm['true_positives']}** | **FN = {cm['false_negatives']}** |
| **Actual Benign ({summary['benign_test_cases']})** | **FP = {cm['false_positives']}** | **TN = {cm['true_negatives']}** |

---

## 4. Limitations of Heuristic Detection & Error Analysis

Heuristic and pattern-based security scanners provide fast, deterministic protection (averaging `{prot['average_latency_ms']} ms` per request) without external API dependencies, but they have inherent limitations compared to semantic analysis:

### 4.1 Observed False Positives (Benign Prompts Flagged: `{err['false_positives_count']}`)
While our contextual dampener successfully allowed defensive/educational inquiries (such as *"How do security engineers defend against..."*), benign prompts that embed literal imperative attack phrases inside creative writing or translation tasks without interrogative framing triggered heuristic rules:
{fp_rows}

### 4.2 Observed Missed Attacks / False Negatives (Attacks Allowed: `{err['false_negatives_count']}`)
Novel metaphoric or purely semantic prompt extraction attempts that avoid known structural keywords bypassed regex heuristics:
{fn_rows}

---

## 5. Generated Artifacts

- **Detailed Per-Case CSV:** `reports/evaluation_results.csv`
- **Summary Metrics JSON:** `reports/evaluation_summary.json`
- **Comparative Bar Chart:** `reports/comparison_chart.html`
- **Confusion Matrix Chart:** `reports/confusion_matrix.html`
"""
    report_path = out_dir / "experiment_report.md"
    report_path.write_text(report_md, encoding="utf-8")
    return report_md


def run_experimental_evaluation(
    out_dir: Path = REPORTS_DIR,
    db_path: Path = DB_PATH,
    record_to_audit_db: bool = False,
    policy_override: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Execute Experiment A (Unprotected Baseline) and Experiment B (Protected Gateway)
    across the full 450-case dataset and save all reports.
    """
    dataset = load_evaluation_dataset()
    results_rows: List[Dict[str, Any]] = []

    for item in dataset:
        prompt = item["prompt"]

        # Experiment A: Unprotected Baseline
        unprot = process_unprotected_baseline(prompt, policy=policy_override)

        # Experiment B: Protected SecureAI Gateway
        gw_req = GatewayRequest(
            prompt=prompt,
            client_id="eval-runner",
            policy_override=policy_override,
        )
        prot = process_gateway_request(
            gw_req,
            db_path=db_path,
            record_audit=record_to_audit_db,
            enforce_rate_limit=False,
        )

        sensitive_redacted = (
            prot.redacted_prompt != prompt and "[REDACTED_" in prot.redacted_prompt
        )

        results_rows.append(
            {
                "id": item["id"],
                "label": item["label"],
                "category": item["category"],
                "expected_outcome": item["expected_outcome"],
                "unprotected_decision": unprot["decision"],
                "unprotected_latency_ms": unprot["processing_latency_ms"],
                "unprotected_attack_succeeded": item["label"] in ("attack", "sensitive"),
                "protected_decision": prot.gateway_decision,
                "protected_risk_score": prot.risk_score,
                "protected_risk_level": prot.risk_level,
                "protected_threat_category": prot.threat_category,
                "matched_rules": ",".join(prot.matched_security_rules),
                "sensitive_redacted": sensitive_redacted,
                "protected_latency_ms": prot.processing_latency_ms,
                "prompt": prompt,
                "redacted_prompt": prot.redacted_prompt,
                "explanation": item["explanation"],
            }
        )

    summary = compute_evaluation_metrics(results_rows)

    # Save CSV
    df = pd.DataFrame(results_rows)
    df.to_csv(out_dir / "evaluation_results.csv", index=False, encoding="utf-8")

    # Save JSON
    (out_dir / "evaluation_summary.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    # Save Charts & Markdown Report
    _generate_charts(summary, out_dir)
    _generate_markdown_report(summary, out_dir)

    return summary


if __name__ == "__main__":
    summary_res = run_experimental_evaluation(record_to_audit_db=True)
    print(json.dumps(summary_res["protected_gateway"], indent=2))
