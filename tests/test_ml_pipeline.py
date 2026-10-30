"""Tests for ForensicLens ML intelligence subsystem."""

import tempfile
import unittest
from pathlib import Path

import numpy as np

from forensiclens.ml.dataset import (
    FEATURE_COLUMNS,
    build_dataset_from_report,
    extract_features_from_event,
    extract_features_from_track,
)
from forensiclens.ml.evaluation import evaluate_supervised, evaluate_unsupervised
from forensiclens.ml.predict import ForensicPredictor, enrich_report_with_ml
from forensiclens.ml.train import ForensicAnomalyPipeline, train_and_select_model


class MLPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sample_track = {
            "parent_evidence_id": "ev-video-1",
            "track_id": 1,
            "class": "person",
            "duration_seconds": 15.0,
            "mean_confidence": 0.85,
            "max_confidence": 0.92,
            "number_of_detections": 12,
            "displacement_pixels": 120.0,
            "entry_edge": "left",
            "exit_edge": "right",
            "object_count_in_window": 12,
            "event_frequency_in_window": 0.8,
        }

        self.sample_event = {
            "event_id": "fe-video-1-movement_detected-000010-0001",
            "parent_evidence_id": "ev-video-1",
            "event_type": "movement_detected",
            "confidence": 0.88,
            "video_timestamp_seconds": 5.0,
            "frame_references": [
                {"frame_index": 10, "video_relative_timestamp_seconds": 5.0},
                {"frame_index": 20, "video_relative_timestamp_seconds": 10.0},
            ],
            "movement": {"displacement_pixels": 80.0, "speed_pixels_per_second": 16.0},
        }

    def test_feature_extraction_structure(self) -> None:
        track_feats = extract_features_from_track(self.sample_track)
        self.assertEqual(len(track_feats), len(FEATURE_COLUMNS))
        self.assertEqual(track_feats["is_person"], 1.0)
        self.assertEqual(track_feats["is_vehicle"], 0.0)
        self.assertEqual(track_feats["has_entry_edge"], 1.0)
        self.assertEqual(track_feats["duration_seconds"], 15.0)

        event_feats = extract_features_from_event(self.sample_event)
        self.assertEqual(len(event_feats), len(FEATURE_COLUMNS))
        self.assertEqual(event_feats["displacement_pixels"], 80.0)

    def test_missing_and_corrupt_features_handled_safely(self) -> None:
        corrupt_track = {"class": None, "duration_seconds": "invalid", "mean_confidence": None}
        feats = extract_features_from_track(corrupt_track)
        self.assertEqual(feats["duration_seconds"], 0.0)
        self.assertEqual(feats["mean_confidence"], 0.5)
        self.assertFalse(np.isnan(feats["mean_velocity_pixels_per_second"]))

    def test_dataset_construction_and_hash(self) -> None:
        report = {
            "track_summary": [self.sample_track],
            "forensic_events": [self.sample_event],
        }
        matrix, records, cols, dset_hash = build_dataset_from_report(report)
        self.assertEqual(matrix.shape, (2, len(FEATURE_COLUMNS)))
        self.assertEqual(len(records), 2)
        self.assertEqual(cols, FEATURE_COLUMNS)
        self.assertEqual(len(dset_hash), 64)

    def test_training_and_model_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            # Generate synthetic forensic feature matrix
            rng = np.random.RandomState(42)
            nominal_data = rng.normal(loc=10.0, scale=2.0, size=(30, len(FEATURE_COLUMNS)))
            # Add a couple of anomalous rows
            nominal_data[0] = nominal_data[0] * 5.0

            pipeline, metadata = train_and_select_model(
                nominal_data,
                dataset_source="unit_test_synthetic",
                dataset_hash="test_hash_123",
                models_dir=tmp_dir,
            )

            self.assertTrue(pipeline.fitted)
            self.assertEqual(metadata["model_name"], "IsolationForest_Forensic_Anomaly")
            self.assertEqual(metadata["mode"], "UNSUPERVISED")
            self.assertIn("isolation_forest", metadata["candidate_comparison"])
            self.assertIn("local_outlier_factor", metadata["candidate_comparison"])
            self.assertTrue(Path(metadata["model_file_path"]).is_file())

            # Test inference via predictor
            predictor = ForensicPredictor(
                model_path=Path(tmp_dir) / "forensic_model.joblib",
                metadata_path=Path(tmp_dir) / "forensic_model_metadata.json",
            )
            self.assertTrue(predictor.pipeline is not None)

            pred = predictor.predict_track(self.sample_track)
            self.assertIn("anomaly_score", pred)
            self.assertIn(pred["review_priority"], {"high", "medium", "low"})
            self.assertIn(pred["classification"], {"anomaly", "nominal"})
            self.assertIn("top_deviating_features", pred["explanation"])

    def test_evaluation_metrics(self) -> None:
        scores = np.array([0.1, 0.2, 0.3, 0.8, 0.9])
        preds = np.array([1, 1, 1, -1, -1])
        unsupervised_res = evaluate_unsupervised(scores, preds, inference_time_seconds=0.01, threshold=0.65)
        self.assertEqual(unsupervised_res["sample_count"], 5)
        self.assertEqual(unsupervised_res["anomaly_count"], 2)
        self.assertEqual(unsupervised_res["anomaly_rate"], 0.4)

        y_true = np.array([0, 0, 1, 1])
        y_pred = np.array([0, 1, 1, 1])
        supervised_res = evaluate_supervised(y_true, y_pred, inference_time_seconds=0.01)
        self.assertEqual(supervised_res["sample_count"], 4)
        self.assertGreater(supervised_res["accuracy"], 0.5)

    def test_no_target_leakage(self) -> None:
        # Verify FEATURE_COLUMNS contains NO triage labels or rule scores
        leakage_candidates = {"triage_score", "review_priority", "crime_probability", "label", "target"}
        for col in FEATURE_COLUMNS:
            self.assertNotIn(col.lower(), leakage_candidates)


if __name__ == "__main__":
    unittest.main()
