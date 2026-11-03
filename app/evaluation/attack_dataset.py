"""
Phase 10: Real-World Security Evaluation Dataset Loader.

Loads the 450 real-world benchmark test cases curated from public Hugging Face datasets:
- 100 Benign prompts (category: benign_general) from deepset/prompt-injections & jackhhao/jailbreak-classification
- 50 Difficult benign prompts (category: difficult_benign) from deepset/prompt-injections & jackhhao/jailbreak-classification
- 100 Direct prompt injection attempts (category: direct_prompt_injection) from deepset/prompt-injections & Lakera/gandalf_ignore_instructions
- 100 Instruction-override or jailbreak attempts (category: jailbreak_override) from jackhhao/jailbreak-classification
- 100 Sensitive-data test cases (category: sensitive_data) from ai4privacy/pii-masking-200k
"""
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple

from app.config import DATA_DIR, PROJECT_DATA_DIR
from app.evaluation.real_dataset_loader import build_and_save_real_datasets

ATTACK_CASES_PATH = DATA_DIR / "attack_test_cases.json"
BENIGN_CASES_PATH = DATA_DIR / "benign_test_cases.json"


def generate_and_save_datasets(
    attack_path: Path = ATTACK_CASES_PATH,
    benign_path: Path = BENIGN_CASES_PATH,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Load the 450 real-world evaluation test cases (fetching from Hugging Face if not yet cached) and write to target paths."""
    proj_atk = PROJECT_DATA_DIR / "attack_test_cases.json"
    proj_ben = PROJECT_DATA_DIR / "benign_test_cases.json"

    if not proj_atk.exists() or not proj_ben.exists():
        build_and_save_real_datasets(PROJECT_DATA_DIR)

    benign_all = json.loads(proj_ben.read_text(encoding="utf-8"))
    attack_all = json.loads(proj_atk.read_text(encoding="utf-8"))

    if len(benign_all) != 150 or len(attack_all) != 300:
        build_and_save_real_datasets(PROJECT_DATA_DIR)
        benign_all = json.loads(proj_ben.read_text(encoding="utf-8"))
        attack_all = json.loads(proj_atk.read_text(encoding="utf-8"))

    if benign_path.resolve() != proj_ben.resolve():
        benign_path.parent.mkdir(parents=True, exist_ok=True)
        benign_path.write_text(json.dumps(benign_all, indent=2, ensure_ascii=False), encoding="utf-8")
    if attack_path.resolve() != proj_atk.resolve():
        attack_path.parent.mkdir(parents=True, exist_ok=True)
        attack_path.write_text(json.dumps(attack_all, indent=2, ensure_ascii=False), encoding="utf-8")

    return benign_all, attack_all


def load_evaluation_dataset(
    attack_path: Path = ATTACK_CASES_PATH,
    benign_path: Path = BENIGN_CASES_PATH,
) -> List[Dict[str, Any]]:
    """Load the full 450-case real-world evaluation dataset."""
    proj_atk = PROJECT_DATA_DIR / "attack_test_cases.json"
    proj_ben = PROJECT_DATA_DIR / "benign_test_cases.json"
    if proj_atk.exists() and proj_ben.exists():
        benign_all = json.loads(proj_ben.read_text(encoding="utf-8"))
        attack_all = json.loads(proj_atk.read_text(encoding="utf-8"))
        if len(benign_all) == 150 and len(attack_all) == 300:
            return benign_all + attack_all
    benign_all, attack_all = generate_and_save_datasets(attack_path, benign_path)
    return benign_all + attack_all
