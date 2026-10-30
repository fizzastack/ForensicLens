"""ForensicLens ML subsystem for event anomaly scoring and review triage."""

from .dataset import FEATURE_COLUMNS, build_dataset_from_report, extract_features_from_event, extract_features_from_track
from .evaluation import evaluate_supervised, evaluate_unsupervised
from .predict import ForensicPredictor, enrich_report_with_ml
from .train import ForensicAnomalyPipeline, train_and_select_model

__all__ = [
    "FEATURE_COLUMNS",
    "ForensicAnomalyPipeline",
    "ForensicPredictor",
    "build_dataset_from_report",
    "enrich_report_with_ml",
    "evaluate_supervised",
    "evaluate_unsupervised",
    "extract_features_from_event",
    "extract_features_from_track",
    "train_and_select_model",
]
