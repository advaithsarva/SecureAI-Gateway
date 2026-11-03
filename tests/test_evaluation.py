"""Phase 13: Tests for Phase 10 Dataset Generation and Phase 11 Experimental Evaluation."""
from pathlib import Path
import tempfile
from app.evaluation.attack_dataset import generate_and_save_datasets
from app.evaluation.evaluator import run_experimental_evaluation


def test_450_dataset_generation_and_evaluation():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_str:
        tmp_path = Path(tmp_str)
        atk_path = tmp_path / "attack_test_cases.json"
        ben_path = tmp_path / "benign_test_cases.json"
        benign_cases, attack_cases = generate_and_save_datasets(atk_path, ben_path)

        # Verify dataset sizes required in Phase 10:
        # 100 benign + 50 difficult benign = 150 benign
        # 100 direct injection + 100 jailbreak + 100 sensitive = 300 threat/sensitive
        assert len(benign_cases) == 150
        assert len(attack_cases) == 300

        out_dir = tmp_path / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        db_path = tmp_path / "eval_audit.db"

        summary = run_experimental_evaluation(
            out_dir=out_dir,
            db_path=db_path,
            record_to_audit_db=False,
        )

        assert summary["total_test_cases"] == 450
        prot = summary["protected_gateway"]
        assert prot["attack_detection_rate_pct"] >= 95.0
        assert prot["sensitive_data_detection_accuracy_pct"] == 100.0
        assert prot["false_positive_rate_pct"] <= 5.0
        assert (out_dir / "evaluation_results.csv").exists()
        assert (out_dir / "evaluation_summary.json").exists()
        assert (out_dir / "experiment_report.md").exists()
