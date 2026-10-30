"""ForensicLens Machine Learning subsystem: Evaluation metrics."""

from __future__ import annotations

from typing import Any
import numpy as np


def evaluate_unsupervised(
    scores: np.ndarray,
    predictions: np.ndarray,
    inference_time_seconds: float,
    threshold: float = 0.5,
) -> dict[str, Any]:
    """Evaluate an unsupervised anomaly model's score distribution and performance."""
    sample_count = len(scores)
    if sample_count == 0:
        return {
            "mode": "UNSUPERVISED",
            "sample_count": 0,
            "anomaly_count": 0,
            "anomaly_rate": 0.0,
            "score_distribution": {
                "min": 0.0, "p25": 0.0, "median": 0.0, "p75": 0.0, "max": 0.0,
                "mean": 0.0, "std": 0.0,
            },
            "threshold": threshold,
            "inference_time_seconds": inference_time_seconds,
            "inference_fps": 0.0,
        }

    anomalies = np.sum(predictions == -1) if -1 in predictions else np.sum(scores >= threshold)
    anomaly_rate = float(anomalies) / sample_count

    score_dist = {
        "min": float(np.min(scores)),
        "p25": float(np.percentile(scores, 25)),
        "median": float(np.median(scores)),
        "p75": float(np.percentile(scores, 75)),
        "max": float(np.max(scores)),
        "mean": float(np.mean(scores)),
        "std": float(np.std(scores)),
    }

    fps = float(sample_count) / max(inference_time_seconds, 1e-6)

    return {
        "mode": "UNSUPERVISED",
        "sample_count": sample_count,
        "anomaly_count": int(anomalies),
        "anomaly_rate": round(anomaly_rate, 4),
        "score_distribution": {k: round(v, 4) for k, v in score_dist.items()},
        "threshold": round(threshold, 4),
        "inference_time_seconds": round(inference_time_seconds, 6),
        "inference_fps": round(fps, 2),
    }


def evaluate_supervised(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    inference_time_seconds: float,
) -> dict[str, Any]:
    """Evaluate a supervised classification model with standard forensic evaluation metrics."""
    from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

    acc = float(accuracy_score(y_true, y_pred))
    p, r, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="weighted", zero_division=0)
    cm = confusion_matrix(y_true, y_pred).tolist()
    unique, counts = np.unique(y_true, return_counts=True)
    class_dist = {str(k): int(v) for k, v in zip(unique, counts)}

    return {
        "mode": "SUPERVISED",
        "sample_count": len(y_true),
        "accuracy": round(acc, 4),
        "precision": round(float(p), 4),
        "recall": round(float(r), 4),
        "f1_score": round(float(f1), 4),
        "confusion_matrix": cm,
        "class_distribution": class_dist,
        "inference_time_seconds": round(inference_time_seconds, 6),
    }
