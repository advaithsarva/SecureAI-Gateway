"""Scikit-learn Machine Learning Prompt Injection & Jailbreak Classifier.

Trains a calibrated TF-IDF (word + character n-gram) LinearSVC classifier on the
disjoint real-world training corpus (`data/training_corpus.json` curated from
Hugging Face `deepset/prompt-injections`, `jackhhao/jailbreak-classification`, and
`Lakera/gandalf_ignore_instructions`).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import joblib
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.svm import LinearSVC

from app.config import DATA_DIR, PROJECT_DATA_DIR


MODEL_FILENAME = "prompt_injection_ml_model.joblib"


class MLPromptInjectionDetector:
    """Hybrid TF-IDF + Calibrated LinearSVC detector for real-world prompt injections and jailbreaks."""

    def __init__(self, threshold: float = 0.52) -> None:
        self.threshold = threshold
        self._pipeline: Optional[Pipeline] = None
        self._loaded = False

    def _get_model_paths(self) -> Tuple[Path, Path]:
        return PROJECT_DATA_DIR / MODEL_FILENAME, DATA_DIR / MODEL_FILENAME

    def ensure_loaded(self) -> bool:
        if self._loaded and self._pipeline is not None:
            return True

        proj_model, runtime_model = self._get_model_paths()
        for candidate in (proj_model, runtime_model):
            if candidate.exists():
                try:
                    self._pipeline = joblib.load(candidate)
                    self._loaded = True
                    return True
                except Exception:
                    pass

        return self.train_and_save()

    def train_and_save(self) -> bool:
        train_path = PROJECT_DATA_DIR / "training_corpus.json"
        if not train_path.exists():
            train_path = DATA_DIR / "training_corpus.json"
        if not train_path.exists():
            return False

        corpus = json.loads(train_path.read_text(encoding="utf-8"))
        if not corpus:
            return False

        texts = [row["text"] for row in corpus]
        labels = [int(row["label"]) for row in corpus]

        features = FeatureUnion(
            [
                (
                    "word_tfidf",
                    TfidfVectorizer(
                        ngram_range=(1, 3),
                        max_features=25000,
                        sublinear_tf=True,
                        strip_accents="unicode",
                    ),
                ),
                (
                    "char_tfidf",
                    TfidfVectorizer(
                        analyzer="char_wb",
                        ngram_range=(3, 5),
                        max_features=35000,
                        sublinear_tf=True,
                    ),
                ),
            ]
        )

        base_svc = LinearSVC(C=1.5, class_weight="balanced", random_state=42)
        pipeline = Pipeline(
            [
                ("features", features),
                ("classifier", CalibratedClassifierCV(base_svc, cv=5)),
            ]
        )
        pipeline.fit(texts, labels)
        self._pipeline = pipeline
        self._loaded = True

        proj_model, runtime_model = self._get_model_paths()
        for target in (proj_model, runtime_model):
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                joblib.dump(pipeline, target)
                break
            except OSError:
                continue
        return True

    def predict(self, prompt: str) -> Dict[str, Any]:
        """Return ML probability score [0.0, 1.0] and detection flag."""
        if not prompt or len(prompt.strip()) < 6:
            return {"detected": False, "probability": 0.0}
        if not self.ensure_loaded() or self._pipeline is None:
            return {"detected": False, "probability": 0.0}

        prob = float(self._pipeline.predict_proba([prompt])[0][1])
        return {
            "detected": prob >= self.threshold,
            "probability": round(prob, 4),
        }


default_ml_detector = MLPromptInjectionDetector()
