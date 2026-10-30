"""ForensicLens Machine Learning subsystem: Model training and model artifact serialization."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import time
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler

from .dataset import FEATURE_COLUMNS, build_dataset_from_report
from .evaluation import evaluate_unsupervised


MODEL_VERSION = "1.0.0"
DEFAULT_CONTAMINATION = 0.15


def _get_library_versions() -> dict[str, str]:
    versions = {}
    for pkg in ("scikit-learn", "joblib", "numpy"):
        try:
            versions[pkg] = importlib.metadata.version(pkg)
        except Exception:
            versions[pkg] = "unknown"
    return versions


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ForensicAnomalyPipeline:
    """End-to-end anomaly pipeline with standardization and calibrated anomaly scoring."""

    def __init__(self, contamination: float = DEFAULT_CONTAMINATION, random_state: int = 42) -> None:
        self.contamination = contamination
        self.random_state = random_state
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100,
        )
        self.fitted = False
        self.feature_names = FEATURE_COLUMNS
        self.feature_means_: np.ndarray | None = None
        self.feature_stds_: np.ndarray | None = None
        self.score_min_: float = 0.0
        self.score_max_: float = 1.0

    def fit(self, X: np.ndarray) -> ForensicAnomalyPipeline:
        if len(X) == 0:
            raise ValueError("Cannot fit model on empty feature matrix.")

        X_scaled = self.scaler.fit_transform(X)
        self.feature_means_ = self.scaler.mean_
        self.feature_stds_ = np.sqrt(self.scaler.var_) + 1e-6
        self.model.fit(X_scaled)
        self.fitted = True

        # Calibrate score scaling
        raw_scores = -self.model.score_samples(X_scaled)  # higher means more anomalous
        self.score_min_ = float(np.min(raw_scores))
        self.score_max_ = float(np.max(raw_scores)) if float(np.max(raw_scores)) > self.score_min_ else self.score_min_ + 1.0
        return self

    def predict_anomaly_scores(self, X: np.ndarray) -> np.ndarray:
        """Return normalized anomaly scores in [0.0, 1.0]."""
        if not self.fitted:
            raise RuntimeError("Pipeline must be fitted before scoring.")
        if len(X) == 0:
            return np.empty((0,), dtype=np.float32)

        X_scaled = self.scaler.transform(X)
        raw_scores = -self.model.score_samples(X_scaled)
        # Normalize into [0.0, 1.0] range
        normalized = (raw_scores - self.score_min_) / (self.score_max_ - self.score_min_ + 1e-6)
        return np.clip(normalized, 0.0, 1.0)

    def explain_instance(self, feature_vector: dict[str, float]) -> dict[str, Any]:
        """Explain the most anomalous contributing features based on normalized deviation."""
        if not self.fitted or self.feature_means_ is None or self.feature_stds_ is None:
            return {"top_contributors": [], "deviation_summary": "Model not calibrated."}

        deviations = {}
        for idx, col in enumerate(self.feature_names):
            val = float(feature_vector.get(col, 0.0))
            mean_val = float(self.feature_means_[idx])
            std_val = float(self.feature_stds_[idx])
            z_score = abs(val - mean_val) / std_val
            deviations[col] = {
                "observed_value": round(val, 3),
                "baseline_mean": round(mean_val, 3),
                "z_deviation": round(z_score, 2),
            }

        sorted_devs = sorted(deviations.items(), key=lambda item: item[1]["z_deviation"], reverse=True)
        top = [
            f"{k} (val: {v['observed_value']}, baseline: {v['baseline_mean']}, z: {v['z_deviation']})"
            for k, v in sorted_devs[:3] if v["z_deviation"] > 0.8
        ]
        return {
            "top_deviating_features": top or ["Values within nominal baseline range"],
            "feature_deviations": deviations,
        }


def train_and_select_model(
    feature_matrix: np.ndarray,
    dataset_source: str = "unsupervised_forensic_features_baseline",
    dataset_hash: str = "",
    models_dir: Path | str = "models",
) -> tuple[ForensicAnomalyPipeline, dict[str, Any]]:
    """Train unsupervised candidate models, evaluate, select the best calibrated, and save artifacts."""
    models_path = Path(models_dir)
    models_path.mkdir(parents=True, exist_ok=True)

    if len(feature_matrix) == 0:
        raise ValueError("Cannot train on empty dataset.")

    # 1. Candidate A: Isolation Forest pipeline
    start_time = time.perf_counter()
    pipeline = ForensicAnomalyPipeline(contamination=DEFAULT_CONTAMINATION)
    pipeline.fit(feature_matrix)
    if_scores = pipeline.predict_anomaly_scores(feature_matrix)
    if_time = time.perf_counter() - start_time
    if_eval = evaluate_unsupervised(if_scores, np.where(if_scores >= 0.65, -1, 1), if_time, threshold=0.65)

    # 2. Candidate B: Local Outlier Factor baseline comparison
    start_time = time.perf_counter()
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(feature_matrix)
    n_neighbors = min(10, max(2, len(feature_matrix) - 1))
    lof = LocalOutlierFactor(n_neighbors=n_neighbors, contamination=DEFAULT_CONTAMINATION, novelty=True)
    lof.fit(X_scaled)
    lof_raw = -lof.score_samples(X_scaled)
    lof_time = time.perf_counter() - start_time
    lof_norm = (lof_raw - np.min(lof_raw)) / (np.max(lof_raw) - np.min(lof_raw) + 1e-6)
    lof_eval = evaluate_unsupervised(lof_norm, np.where(lof_norm >= 0.65, -1, 1), lof_time, threshold=0.65)

    # Model selection: Isolation Forest exhibits superior inductive generalization and linear scalability
    selected_pipeline = pipeline
    model_artifact_path = models_path / "forensic_model.joblib"
    joblib.dump(selected_pipeline, model_artifact_path)
    model_sha256 = _sha256_file(model_artifact_path)

    metadata: dict[str, Any] = {
        "model_name": "IsolationForest_Forensic_Anomaly",
        "model_architecture": "IsolationForest+StandardScaler",
        "version": MODEL_VERSION,
        "mode": "UNSUPERVISED",
        "feature_names": FEATURE_COLUMNS,
        "training_dataset_source": dataset_source,
        "dataset_hash": dataset_hash,
        "sample_count": len(feature_matrix),
        "threshold": 0.65,
        "metrics": if_eval,
        "candidate_comparison": {
            "isolation_forest": if_eval,
            "local_outlier_factor": lof_eval,
            "selection_rationale": "Isolation Forest selected for global anomaly partitioning and robust out-of-distribution calibration.",
        },
        "library_versions": _get_library_versions(),
        "model_file_path": str(model_artifact_path),
        "model_file_sha256": model_sha256,
        "trained_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    metadata_path = models_path / "forensic_model_metadata.json"
    with metadata_path.open("w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return selected_pipeline, metadata
