"""ForensicLens Machine Learning subsystem: Model loading and event inference integration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from .dataset import FEATURE_COLUMNS, extract_features_from_event, extract_features_from_track
from .train import ForensicAnomalyPipeline


class ForensicPredictor:
    """Predictor wrapper that applies the trained anomaly model to forensic events and tracks."""

    def __init__(self, model_path: Path | str = "models/forensic_model.joblib", metadata_path: Path | str = "models/forensic_model_metadata.json") -> None:
        self.model_path = Path(model_path)
        self.metadata_path = Path(metadata_path)
        self.pipeline: ForensicAnomalyPipeline | None = None
        self.metadata: dict[str, Any] = {}
        self.load()

    def load(self) -> bool:
        """Load trained pipeline and metadata if available."""
        if self.model_path.is_file() and self.metadata_path.is_file():
            try:
                self.pipeline = joblib.load(self.model_path)
                with self.metadata_path.open("r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                return True
            except Exception:
                self.pipeline = None
                self.metadata = {}
        return False

    def predict_track(self, track: dict[str, Any], index: int = 0) -> dict[str, Any]:
        """Generate ML prediction output for a track summary."""
        feats = extract_features_from_track(track, index)
        if not self.pipeline:
            return self._default_fallback(feats, track.get("parent_evidence_id"), track_id=track.get("track_id"))

        row = np.array([[feats[col] for col in FEATURE_COLUMNS]], dtype=np.float32)
        score = float(self.pipeline.predict_anomaly_scores(row)[0])
        explanation = self.pipeline.explain_instance(feats)
        threshold = float(self.metadata.get("threshold", 0.65))

        priority = "high" if score >= threshold else ("medium" if score >= 0.35 else "low")
        classification = "anomaly" if score >= threshold else "nominal"
        confidence = round(abs(score - 0.5) * 2.0, 4)

        return {
            "model": self.metadata.get("model_name", "IsolationForest_Forensic_Anomaly"),
            "model_version": self.metadata.get("version", "1.0.0"),
            "anomaly_score": round(score, 4),
            "review_priority": priority,
            "classification": classification,
            "model_confidence": confidence,
            "feature_inputs": feats,
            "explanation": explanation,
            "parent_evidence_id": track.get("parent_evidence_id"),
            "track_id": track.get("track_id"),
            "event_id": None,
        }

    def predict_event(self, event: dict[str, Any], index: int = 0) -> dict[str, Any]:
        """Generate ML prediction output for a forensic event."""
        feats = extract_features_from_event(event, index)
        if not self.pipeline:
            return self._default_fallback(feats, event.get("parent_evidence_id"), event_id=event.get("event_id"))

        row = np.array([[feats[col] for col in FEATURE_COLUMNS]], dtype=np.float32)
        score = float(self.pipeline.predict_anomaly_scores(row)[0])
        explanation = self.pipeline.explain_instance(feats)
        threshold = float(self.metadata.get("threshold", 0.65))

        priority = "high" if score >= threshold else ("medium" if score >= 0.35 else "low")
        classification = "anomaly" if score >= threshold else "nominal"
        confidence = round(abs(score - 0.5) * 2.0, 4)

        return {
            "model": self.metadata.get("model_name", "IsolationForest_Forensic_Anomaly"),
            "model_version": self.metadata.get("version", "1.0.0"),
            "anomaly_score": round(score, 4),
            "review_priority": priority,
            "classification": classification,
            "model_confidence": confidence,
            "feature_inputs": feats,
            "explanation": explanation,
            "parent_evidence_id": event.get("parent_evidence_id"),
            "track_id": event.get("track_id"),
            "event_id": event.get("event_id"),
        }

    def _default_fallback(self, feats: dict[str, float], parent_evidence_id: str | None, track_id: int | None = None, event_id: str | None = None) -> dict[str, Any]:
        return {
            "model": "rule_based_fallback",
            "model_version": "none",
            "anomaly_score": 0.0,
            "review_priority": "low",
            "classification": "nominal",
            "model_confidence": 0.0,
            "feature_inputs": feats,
            "explanation": {"top_deviating_features": ["ML model not loaded; nominal fallback."]},
            "parent_evidence_id": parent_evidence_id,
            "track_id": track_id,
            "event_id": event_id,
        }


def enrich_report_with_ml(report_data: dict[str, Any], predictor: ForensicPredictor | None = None) -> dict[str, Any]:
    """Enrich forensic events and track summaries in the report with ML predictions and explanations."""
    if predictor is None:
        predictor = ForensicPredictor()

    events = report_data.get("forensic_events", [])
    for idx, event in enumerate(events):
        pred = predictor.predict_event(event, idx)
        event["ml_inference"] = pred
        # Also integrate score & priority at top level for easy inspector access
        event["anomaly_score"] = pred["anomaly_score"]
        event["review_priority"] = pred["review_priority"]
        event["model_confidence"] = pred["model_confidence"]

    tracks = report_data.get("track_summary", [])
    for idx, track in enumerate(tracks):
        pred = predictor.predict_track(track, idx)
        track["ml_inference"] = pred
        track["anomaly_score"] = pred["anomaly_score"]
        track["review_priority"] = pred["review_priority"]

    # Add dedicated ml_intelligence section to the report
    ml_section: dict[str, Any] = {
        "status": "available" if predictor.pipeline is not None else "model_not_trained",
        "model_metadata": predictor.metadata,
        "total_inferences": len(events) + len(tracks),
        "high_priority_inferences": sum(1 for e in events if e.get("review_priority") == "high") + sum(1 for t in tracks if t.get("review_priority") == "high"),
        "medium_priority_inferences": sum(1 for e in events if e.get("review_priority") == "medium") + sum(1 for t in tracks if t.get("review_priority") == "medium"),
        "low_priority_inferences": sum(1 for e in events if e.get("review_priority") == "low") + sum(1 for t in tracks if t.get("review_priority") == "low"),
    }
    report_data["ml_intelligence"] = ml_section
    return report_data
