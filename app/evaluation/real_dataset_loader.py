"""Real-World Dataset Loader from Hugging Face Public Benchmarks.

Downloads and curates real benchmark datasets from Hugging Face Datasets Server:
1. deepset/prompt-injections (Real prompt injection & benign prompts)
2. jackhhao/jailbreak-classification (Real in-the-wild jailbreak & benign prompts)
3. Lakera/gandalf_ignore_instructions (Real adversarial prompt injection attacks)
4. ai4privacy/pii-masking-200k (Real PII benchmark prompts with ground-truth entity spans)

Strictly separates the 450-case evaluation dataset (attack_test_cases.json & benign_test_cases.json)
from the training corpus (training_corpus.json) with zero text overlap.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple
import httpx

from app.config import PROJECT_DATA_DIR
from app.security.privacy_scanner import default_privacy_scanner


HF_API_URL = "https://datasets-server.huggingface.co/rows"


def _norm_text(text: str) -> str:
    return " ".join(text.strip().lower().split())


def fetch_hf_rows(dataset: str, split: str, max_rows: int = 1200, config: str = "default") -> List[Dict[str, Any]]:
    """Fetch rows from the official Hugging Face Datasets Server REST API."""
    rows: List[Dict[str, Any]] = []
    offset = 0
    with httpx.Client(timeout=30.0) as client:
        while offset < max_rows:
            length = min(100, max_rows - offset)
            resp = client.get(
                HF_API_URL,
                params={
                    "dataset": dataset,
                    "config": config,
                    "split": split,
                    "offset": offset,
                    "length": length,
                },
            )
            resp.raise_for_status()
            payload = resp.json()
            batch = [item["row"] for item in payload.get("rows", [])]
            if not batch:
                break
            rows.extend(batch)
            offset += len(batch)
            if len(batch) < length:
                break
    return rows


def _has_difficult_benign_cues(text: str) -> bool:
    """Identify real benign prompts that use roleplay, instruction, or security terminology."""
    t = text.lower()
    cues = (
        "act as",
        "interviewer",
        "instructor",
        "role",
        "system",
        "instruction",
        "security",
        "password",
        "code",
        "python",
        "sql",
        "translate",
        "prompt",
        "assistant",
        "character",
        "simulator",
        "terminal",
        "guide",
        "write",
        "explain",
        "imagine",
        "pretend",
        "expert",
    )
    return any(c in t for c in cues)


def _contains_target_pii(row: Dict[str, Any]) -> Tuple[bool, List[str], List[Dict[str, str]]]:
    """Check if an ai4privacy row contains clean target PII (EMAIL, PHONENUMBER, IPV4, SSN, CREDITCARDNUMBER, PASSWORD)."""
    if row.get("language") != "en":
        return False, [], []
    text = row.get("source_text", "")
    if not text or len(text) < 25 or len(text) > 1000:
        return False, [], []

    target_labels = {"EMAIL", "PHONENUMBER", "IPV4", "SSN", "CREDITCARDNUMBER", "PASSWORD"}
    matched_labels: List[str] = []
    matched_spans: List[Dict[str, str]] = []

    for m in row.get("privacy_mask", []):
        lbl = m.get("label", "")
        val = str(m.get("value", "")).strip()
        if lbl in target_labels and val and val in text:
            if lbl == "EMAIL" and "@" in val and "." in val.split("@")[-1]:
                matched_labels.append(lbl)
                matched_spans.append({"label": lbl, "value": val})
            elif lbl == "IPV4" and val.count(".") == 3:
                matched_labels.append(lbl)
                matched_spans.append({"label": lbl, "value": val})
            elif lbl == "SSN" and len(val) >= 9:
                matched_labels.append(lbl)
                matched_spans.append({"label": lbl, "value": val})
            elif lbl == "CREDITCARDNUMBER" and sum(c.isdigit() for c in val) >= 13:
                matched_labels.append(lbl)
                matched_spans.append({"label": lbl, "value": val})
            elif lbl == "PHONENUMBER" and sum(c.isdigit() for c in val) >= 9:
                matched_labels.append(lbl)
                matched_spans.append({"label": lbl, "value": val})
            elif lbl == "PASSWORD" and len(val) >= 8 and "password" in text.lower():
                matched_labels.append(lbl)
                matched_spans.append({"label": lbl, "value": val})

    if not matched_labels:
        return False, [], []
    return True, sorted(set(matched_labels)), matched_spans


def build_and_save_real_datasets(data_dir: Path = PROJECT_DATA_DIR) -> Dict[str, Any]:
    """Download real Hugging Face datasets and save evaluation & training splits."""
    data_dir.mkdir(parents=True, exist_ok=True)

    print("Fetching deepset/prompt-injections (train & test)...")
    deepset_train = fetch_hf_rows("deepset/prompt-injections", "train", max_rows=600)
    deepset_test = fetch_hf_rows("deepset/prompt-injections", "test", max_rows=200)

    print("Fetching jackhhao/jailbreak-classification (train & test)...")
    jb_train = fetch_hf_rows("jackhhao/jailbreak-classification", "train", max_rows=1100)
    jb_test = fetch_hf_rows("jackhhao/jailbreak-classification", "test", max_rows=300)

    print("Fetching Lakera/gandalf_ignore_instructions (train)...")
    lakera_rows = fetch_hf_rows("Lakera/gandalf_ignore_instructions", "train", max_rows=800)

    print("Fetching ai4privacy/pii-masking-200k (train)...")
    pii_rows = fetch_hf_rows("ai4privacy/pii-masking-200k", "train", max_rows=700)

    used_eval_hashes = set()

    def _claim(text: str) -> bool:
        h = hashlib.sha256(_norm_text(text).encode("utf-8")).hexdigest()
        if h in used_eval_hashes:
            return False
        used_eval_hashes.add(h)
        return True

    # ------------------------------------------------------------------
    # 1. Select 100 Direct Prompt Injection Cases (Real Test/Benchmark Rows)
    # ------------------------------------------------------------------
    injection_cues = (
        "ignore", "disregard", "forget", "override", "system", "prompt",
        "instruction", "password", "secret", "reveal", "print", "repeat",
        "ignoriere", "vergiss", "anweisung", "neue aufgabe", "new task",
        "stop", "instead", "nevermind", "bypass", "rules", "guidelines",
        "jailbreak", "unrestricted", "developer", "confidential", "spell",
    )
    direct_injection_cases: List[Dict[str, Any]] = []
    for idx, r in enumerate(deepset_test):
        if r.get("label") == 1 and len(direct_injection_cases) < 50:
            txt = r["text"].strip()
            if len(txt) >= 15 and any(k in txt.lower() for k in injection_cues) and _claim(txt):
                expl = f"Real prompt injection from deepset/prompt-injections test split (row {idx})."
                direct_injection_cases.append({
                    "id": f"DPI-{len(direct_injection_cases)+1:03d}",
                    "label": "attack",
                    "category": "direct_prompt_injection",
                    "prompt": txt,
                    "expected_outcome": "BLOCK",
                    "expected_threat": True,
                    "expected_decision": "BLOCK",
                    "contains_sensitive_data": False,
                    "source_dataset": "deepset/prompt-injections",
                    "source_split": "test",
                    "explanation": expl,
                    "notes": expl,
                })

    for idx, r in enumerate(lakera_rows[500:], start=500):
        if len(direct_injection_cases) >= 100:
            break
        txt = r["text"].strip()
        if len(txt) >= 15 and any(k in txt.lower() for k in injection_cues) and _claim(txt):
            expl = f"Real Gandalf adversarial injection from Lakera/gandalf_ignore_instructions (row {idx})."
            direct_injection_cases.append({
                "id": f"DPI-{len(direct_injection_cases)+1:03d}",
                "label": "attack",
                "category": "direct_prompt_injection",
                "prompt": txt,
                "expected_outcome": "BLOCK",
                "expected_threat": True,
                "expected_decision": "BLOCK",
                "contains_sensitive_data": False,
                "source_dataset": "Lakera/gandalf_ignore_instructions",
                "source_split": "heldout_eval",
                "explanation": expl,
                "notes": expl,
            })

    # ------------------------------------------------------------------
    # 2. Select 100 Jailbreak & Instruction-Override Cases (Real Test Split)
    # ------------------------------------------------------------------
    jailbreak_cases: List[Dict[str, Any]] = []
    for idx, r in enumerate(jb_test):
        if r.get("type") == "jailbreak" and len(jailbreak_cases) < 100:
            txt = r["prompt"].strip()
            if len(txt) >= 15 and len(txt) <= 8500 and _claim(txt):
                expl = f"Real in-the-wild jailbreak prompt from jackhhao/jailbreak-classification test split (row {idx})."
                jailbreak_cases.append({
                    "id": f"JBK-{len(jailbreak_cases)+1:03d}",
                    "label": "attack",
                    "category": "jailbreak_override",
                    "prompt": txt,
                    "expected_outcome": "BLOCK",
                    "expected_threat": True,
                    "expected_decision": "BLOCK",
                    "contains_sensitive_data": False,
                    "source_dataset": "jackhhao/jailbreak-classification",
                    "source_split": "test",
                    "explanation": expl,
                    "notes": expl,
                })

    for idx in range(len(jb_train) - 1, -1, -1):
        if len(jailbreak_cases) >= 100:
            break
        r = jb_train[idx]
        if r.get("type") == "jailbreak":
            txt = r["prompt"].strip()
            if len(txt) >= 15 and len(txt) <= 8500 and _claim(txt):
                expl = f"Real in-the-wild jailbreak prompt from jackhhao/jailbreak-classification (row {idx})."
                jailbreak_cases.append({
                    "id": f"JBK-{len(jailbreak_cases)+1:03d}",
                    "label": "attack",
                    "category": "jailbreak_override",
                    "prompt": txt,
                    "expected_outcome": "BLOCK",
                    "expected_threat": True,
                    "expected_decision": "BLOCK",
                    "contains_sensitive_data": False,
                    "source_dataset": "jackhhao/jailbreak-classification",
                    "source_split": "heldout_eval",
                    "explanation": expl,
                    "notes": expl,
                })

    # ------------------------------------------------------------------
    # 3. Select 100 Real Sensitive-Data Prompts from ai4privacy/pii-masking-200k
    # ------------------------------------------------------------------
    sensitive_cases: List[Dict[str, Any]] = []
    for idx, r in enumerate(pii_rows):
        if len(sensitive_cases) >= 100:
            break
        ok, labels, spans = _contains_target_pii(r)
        if ok:
            txt = r["source_text"].strip()
            if _claim(txt):
                expl = f"Real PII sample from ai4privacy/pii-masking-200k (id={r.get('id')}, entities={','.join(labels)})."
                sensitive_cases.append({
                    "id": f"SENS-{len(sensitive_cases)+1:03d}",
                    "label": "sensitive",
                    "category": "sensitive_data",
                    "prompt": txt,
                    "expected_outcome": "SANITIZE",
                    "expected_threat": True,
                    "expected_decision": "SANITIZE",
                    "contains_sensitive_data": True,
                    "source_dataset": "ai4privacy/pii-masking-200k",
                    "source_split": "train",
                    "ground_truth_pii_labels": labels,
                    "ground_truth_pii_spans": spans,
                    "explanation": expl,
                    "notes": expl,
                })

    # ------------------------------------------------------------------
    # 4. Select 50 Difficult Benign & 100 Standard Benign Cases (Real Splits)
    # ------------------------------------------------------------------
    difficult_benign_cases: List[Dict[str, Any]] = []
    standard_benign_cases: List[Dict[str, Any]] = []

    benign_pool: List[Tuple[str, str, str, int]] = []
    for idx, r in enumerate(deepset_test):
        if r.get("label") == 0:
            benign_pool.append((r["text"].strip(), "deepset/prompt-injections", "test", idx))
    for idx, r in enumerate(jb_test):
        if r.get("type") == "benign":
            benign_pool.append((r["prompt"].strip(), "jackhhao/jailbreak-classification", "test", idx))
    for idx in range(len(jb_train) - 1, -1, -1):
        r = jb_train[idx]
        if r.get("type") == "benign":
            benign_pool.append((r["prompt"].strip(), "jackhhao/jailbreak-classification", "heldout_eval", idx))
    for idx in range(len(deepset_train) - 1, -1, -1):
        r = deepset_train[idx]
        if r.get("label") == 0:
            benign_pool.append((r["text"].strip(), "deepset/prompt-injections", "heldout_eval", idx))

    for txt, src_ds, src_split, idx in benign_pool:
        if len(txt) < 8 or len(txt) > 8000:
            continue
        if "@" in txt and "." in txt:
            continue
        if default_privacy_scanner.scan_and_redact(txt).detected:
            continue
        if _has_difficult_benign_cues(txt) and len(difficult_benign_cases) < 50:
            if _claim(txt):
                expl = f"Real difficult benign prompt (contains roleplay/technical cues) from {src_ds} ({src_split}, row {idx})."
                difficult_benign_cases.append({
                    "id": f"DBEN-{len(difficult_benign_cases)+1:03d}",
                    "label": "benign",
                    "category": "difficult_benign",
                    "prompt": txt,
                    "expected_outcome": "ALLOW",
                    "expected_threat": False,
                    "expected_decision": "ALLOW",
                    "contains_sensitive_data": False,
                    "source_dataset": src_ds,
                    "source_split": src_split,
                    "explanation": expl,
                    "notes": expl,
                })
        elif len(standard_benign_cases) < 100:
            if _claim(txt):
                expl = f"Real benign prompt from {src_ds} ({src_split}, row {idx})."
                standard_benign_cases.append({
                    "id": f"BEN-{len(standard_benign_cases)+1:03d}",
                    "label": "benign",
                    "category": "benign_general",
                    "prompt": txt,
                    "expected_outcome": "ALLOW",
                    "expected_threat": False,
                    "expected_decision": "ALLOW",
                    "contains_sensitive_data": False,
                    "source_dataset": src_ds,
                    "source_split": src_split,
                    "explanation": expl,
                    "notes": expl,
                })
        if len(difficult_benign_cases) >= 50 and len(standard_benign_cases) >= 100:
            break

    # ------------------------------------------------------------------
    # 5. Build Strictly Disjoint Training Corpus for Scikit-Learn ML Detector
    # ------------------------------------------------------------------
    training_corpus: List[Dict[str, Any]] = []
    seen_train_hashes = set()

    def _add_train(text: str, label: int, source: str) -> None:
        txt = text.strip()
        if len(txt) < 5:
            return
        h = hashlib.sha256(_norm_text(txt).encode("utf-8")).hexdigest()
        if h in used_eval_hashes or h in seen_train_hashes:
            return
        seen_train_hashes.add(h)
        training_corpus.append({"text": txt, "label": int(label), "source": source})

    for r in deepset_train:
        _add_train(r["text"], int(r["label"]), "deepset/prompt-injections:train")
    for r in deepset_test:
        _add_train(r["text"], int(r["label"]), "deepset/prompt-injections:test_unused")
    for r in jb_train:
        lbl = 1 if r.get("type") == "jailbreak" else 0
        _add_train(r["prompt"], lbl, "jackhhao/jailbreak-classification:train")
    for r in jb_test:
        lbl = 1 if r.get("type") == "jailbreak" else 0
        _add_train(r["prompt"], lbl, "jackhhao/jailbreak-classification:test_unused")
    for r in lakera_rows[:550]:
        _add_train(r["text"], 1, "Lakera/gandalf_ignore_instructions:train")

    attack_cases = direct_injection_cases + jailbreak_cases + sensitive_cases
    benign_cases = standard_benign_cases + difficult_benign_cases

    attack_path = data_dir / "attack_test_cases.json"
    benign_path = data_dir / "benign_test_cases.json"
    train_path = data_dir / "training_corpus.json"
    provenance_path = data_dir / "dataset_provenance.json"

    attack_path.write_text(json.dumps(attack_cases, indent=2, ensure_ascii=False), encoding="utf-8")
    benign_path.write_text(json.dumps(benign_cases, indent=2, ensure_ascii=False), encoding="utf-8")
    train_path.write_text(json.dumps(training_corpus, indent=2, ensure_ascii=False), encoding="utf-8")

    provenance = {
        "is_real_world_dataset": True,
        "synthetic_cases_count": 0,
        "total_evaluation_cases": len(attack_cases) + len(benign_cases),
        "breakdown": {
            "benign_general": len(standard_benign_cases),
            "difficult_benign": len(difficult_benign_cases),
            "direct_prompt_injection": len(direct_injection_cases),
            "jailbreak_override": len(jailbreak_cases),
            "sensitive_data": len(sensitive_cases),
        },
        "disjoint_training_corpus_size": len(training_corpus),
        "train_eval_overlap_count": 0,
        "huggingface_sources": [
            {
                "dataset": "deepset/prompt-injections",
                "url": "https://huggingface.co/datasets/deepset/prompt-injections",
                "role": "Direct prompt injection & benign evaluation/training splits",
            },
            {
                "dataset": "jackhhao/jailbreak-classification",
                "url": "https://huggingface.co/datasets/jackhhao/jailbreak-classification",
                "role": "Real in-the-wild jailbreak & benign roleplay evaluation/training splits",
            },
            {
                "dataset": "Lakera/gandalf_ignore_instructions",
                "url": "https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions",
                "role": "Adversarial prompt-injection evaluation/training samples",
            },
            {
                "dataset": "ai4privacy/pii-masking-200k",
                "url": "https://huggingface.co/datasets/ai4privacy/pii-masking-200k",
                "role": "Real English PII benchmark samples with annotated EMAIL, PHONENUMBER, IPV4, SSN, CREDITCARDNUMBER, and PASSWORD spans",
            },
        ],
    }
    provenance_path.write_text(json.dumps(provenance, indent=2, ensure_ascii=False), encoding="utf-8")
    return provenance


if __name__ == "__main__":
    summary = build_and_save_real_datasets()
    print(json.dumps(summary, indent=2))
