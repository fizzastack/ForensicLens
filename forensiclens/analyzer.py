"""Read-only evidence-file analysis for ForensicLens."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from PIL import ExifTags, Image, UnidentifiedImageError

from .correlation import CameraTopology, CorrelationEngine, build_evidence_graph
from .dvr_nvr import analyze_dvr_nvr_evidence
from .dvr_nvr.schema import evidence_id
from .evidence_registry import build_case_integrity
from .forensic_events import aggregate_forensic_events
from .ml import ForensicPredictor, build_dataset_from_report, enrich_report_with_ml, train_and_select_model
from .preservation import assert_output_outside_evidence, capture_integrity, sha256_file, utc_now, verify_evidence
from .timeline import build_timeline
from .video_evidence import discover_video_evidence
from .video_intelligence import analyze_video_intelligence


IMAGE_EXTENSIONS = {
    ".bmp", ".gif", ".heic", ".heif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp",
}
def _utc_timestamp(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat().replace("+00:00", "Z")


def _analysis_timestamp() -> str:
    return utc_now()


def _json_safe(value: Any) -> Any:
    """Convert Pillow EXIF values to values safe to serialize in JSON."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return str(value)


def _extract_image_metadata(path: Path) -> dict[str, Any]:
    try:
        with Image.open(path) as image:
            exif = image.getexif()
            exif_data = {
                ExifTags.TAGS.get(tag_id, str(tag_id)): _json_safe(value)
                for tag_id, value in exif.items()
            }
            return {
                "format": image.format,
                "width": image.width,
                "height": image.height,
                "mode": image.mode,
                "exif": exif_data,
            }
    except (UnidentifiedImageError, OSError, SyntaxError) as error:
        return {"error": f"Unable to read image metadata: {error}"}


def _audit(audit_log: list[dict[str, Any]], timestamp: str, record: dict[str, Any], operation: str, status: str) -> None:
    audit_log.append({
        "timestamp_utc": timestamp,
        "evidence_id": record["evidence_id"],
        "evidence_file": record["relative_path"],
        "operation": operation,
        "source": "analysis_core",
        "status": status,
    })


def analyze_file(
    path: Path,
    evidence_root: Path,
    analysis_timestamp_utc: str | None = None,
    audit_log: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Analyze one evidence file without writing to it."""
    timestamp = analysis_timestamp_utc or _analysis_timestamp()
    log = audit_log if audit_log is not None else []
    record: dict[str, Any] = {
        "relative_path": path.relative_to(evidence_root).as_posix(),
        "filename": path.name,
        "extension": path.suffix.lower(),
        "is_image": path.suffix.lower() in IMAGE_EXTENSIONS,
        "errors": [],
    }

    original_integrity = capture_integrity(path)
    record["original_sha256"] = original_integrity["sha256"]
    record["sha256"] = original_integrity["sha256"]
    record["evidence_id"] = evidence_id(record["original_sha256"], record["relative_path"])
    record["integrity"] = {"pre_processing": original_integrity}
    _audit(log, timestamp, record, "original_sha256_calculated", original_integrity["status"])

    try:
        stat = path.stat()
        record["size_bytes"] = stat.st_size
        record["created_at_utc"] = _utc_timestamp(stat.st_ctime)
        record["modified_at_utc"] = _utc_timestamp(stat.st_mtime)
    except OSError as error:
        record["errors"].append(f"Unable to read file metadata: {error}")
    _audit(log, timestamp, record, "file_metadata_analyzed", "available" if "size_bytes" in record else "unavailable")

    if record["is_image"]:
        image_metadata = _extract_image_metadata(path)
        if "error" in image_metadata:
            record["errors"].append(image_metadata.pop("error"))
        record["image_metadata"] = image_metadata
        _audit(log, timestamp, record, "image_metadata_analyzed", "available" if image_metadata else "unavailable")

    verification = verify_evidence(path, record["original_sha256"])
    record["integrity"]["post_processing"] = verification
    _audit(log, timestamp, record, "post_analysis_hash_verified", verification["status"])

    return record


def build_evidence_report(
    evidence_root: Path,
    video_root: Path | None = None,
    enable_video_intelligence: bool = False,
    video_intelligence_config: dict[str, Any] | None = None,
    forensic_event_config: dict[str, Any] | None = None,
    case_id: str = "CASE-2026-001",
    investigation_title: str = "ForensicLens Digital Evidence Analysis",
    enable_ml: bool = True,
    models_dir: Path | str = "models",
    correlation_config: dict[str, Any] | None = None,
    camera_topology: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Recursively analyze all files beneath an evidence directory."""
    evidence_root = evidence_root.resolve()
    if not evidence_root.is_dir():
        raise NotADirectoryError(f"Evidence directory does not exist: {evidence_root}")

    analysis_timestamp_utc = _analysis_timestamp()
    files = sorted(path for path in evidence_root.rglob("*") if path.is_file())
    audit_log: list[dict[str, Any]] = []
    evidence_files = [analyze_file(path, evidence_root, analysis_timestamp_utc, audit_log) for path in files]
    dvr_nvr_evidence = analyze_dvr_nvr_evidence(evidence_root, evidence_files, analysis_timestamp_utc, audit_log)
    video_evidence = discover_video_evidence(video_root, analysis_timestamp_utc, audit_log) if video_root else {
        "source_roots": [], "read_only_evidence_handling": {"source_evidence_write_policy": "prohibited"},
        "videos": [], "unsupported_videos": [], "derived_artifacts": [], "errors": [],
        "total_videos_discovered": 0, "videos_metadata_extracted": 0, "videos_with_errors": 0,
    }
    video_events = analyze_video_intelligence(video_evidence, analysis_timestamp_utc, audit_log, video_intelligence_config) if enable_video_intelligence else {
        "status": "not_run", "configuration": {}, "runtime": {},
        "performance": {"frames_analyzed": 0, "inference_seconds": 0.0, "inference_fps": 0.0},
        "events": [], "timeline_events": [], "detections_by_class": {}, "track_count": 0,
        "motion_change_event_count": 0, "errors": [], "derived_artifacts": [],
    }
    forensic_aggregation = aggregate_forensic_events(video_events, video_evidence, forensic_event_config) if enable_video_intelligence else {
        "aggregation_version": "1.0", "reproducibility_configuration": {}, "track_summary": [], "forensic_events": [],
        "forensic_features": [], "triage_summary": {"items": [], "high_priority_count": 0, "medium_priority_count": 0, "low_priority_count": 0},
        "timeline_events": [], "errors": [],
    }
    if enable_video_intelligence:
        audit_log.append({
            "timestamp_utc": analysis_timestamp_utc,
            "evidence_id": None,
            "operation": "forensic_event_aggregation_completed",
            "source": "forensic_event_aggregation",
            "status": "completed" if not forensic_aggregation["errors"] else "partial",
        })

    report: dict[str, Any] = {
        "analysis_timestamp_utc": analysis_timestamp_utc,
        "evidence_root": str(evidence_root),
        "total_evidence_files": len(evidence_files),
        "image_file_count": sum(file["is_image"] for file in evidence_files),
        "evidence_files": evidence_files,
        "timeline": build_timeline(evidence_files, analysis_timestamp_utc, video_events["timeline_events"] + forensic_aggregation["timeline_events"]),
        "dvr_nvr_evidence": dvr_nvr_evidence,
        "video_evidence": video_evidence,
        "video_events": video_events,
        "track_summary": forensic_aggregation["track_summary"],
        "forensic_events": forensic_aggregation["forensic_events"],
        "forensic_features": forensic_aggregation["forensic_features"],
        "triage_summary": forensic_aggregation["triage_summary"],
        "correlations": [],
        "evidence_graph": {},
        "reproducibility_configuration": {
            "video_intelligence": video_events.get("configuration", {}),
            "forensic_event_aggregation": forensic_aggregation["reproducibility_configuration"],
            "forensic_event_aggregation_version": forensic_aggregation["aggregation_version"],
        },
        "audit_log": audit_log,
    }

    # Run ML Anomaly Inference & Calibration
    if enable_ml and enable_video_intelligence and (report["forensic_events"] or report["track_summary"]):
        predictor = ForensicPredictor(
            model_path=Path(models_dir) / "forensic_model.joblib",
            metadata_path=Path(models_dir) / "forensic_model_metadata.json",
        )
        if predictor.pipeline is None:
            # Train unsupervised baseline on extracted forensic features
            feat_matrix, _, _, dset_hash = build_dataset_from_report(report)
            if len(feat_matrix) > 0:
                train_and_select_model(
                    feat_matrix,
                    dataset_source="unsupervised_forensic_features_baseline",
                    dataset_hash=dset_hash,
                    models_dir=models_dir,
                )
                predictor.load()

        enrich_report_with_ml(report, predictor)
        audit_log.append({
            "timestamp_utc": analysis_timestamp_utc,
            "evidence_id": None,
            "operation": "ml_intelligence_evaluated",
            "source": "ml_subsystem",
            "status": "completed" if predictor.pipeline is not None else "unavailable",
        })

    # Run Multi-Camera / Intra-Video Correlation Engine
    if report["forensic_events"]:
        topology = CameraTopology.from_dict(camera_topology)
        engine = CorrelationEngine(correlation_config, topology)
        correlations = engine.correlate_events(report["forensic_events"], report["track_summary"])
        report["correlations"] = correlations
        audit_log.append({
            "timestamp_utc": analysis_timestamp_utc,
            "evidence_id": None,
            "operation": "surveillance_event_correlation_completed",
            "source": "correlation_engine",
            "status": "completed",
        })

    # Construct Evidence Relationship Graph
    graph_dict = build_evidence_graph(report, report["correlations"])
    report["evidence_graph"] = graph_dict
    audit_log.append({
        "timestamp_utc": analysis_timestamp_utc,
        "evidence_id": None,
        "operation": "evidence_graph_constructed",
        "source": "evidence_graph",
        "status": "completed",
    })

    case_integrity = build_case_integrity(report, case_id, investigation_title)
    report.update({key: value for key, value in case_integrity.items() if key != "audit_extensions"})
    report["audit_log"].extend(case_integrity["audit_extensions"])
    return report


def write_report(report: dict[str, Any], output_path: Path) -> Path:
    """Write an evidence report outside the evidence directory."""
    evidence_root = report.get("evidence_root")
    if evidence_root:
        assert_output_outside_evidence(output_path, Path(evidence_root))
    for video_root in report.get("video_evidence", {}).get("source_roots", []):
        assert_output_outside_evidence(output_path, Path(video_root))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as report_file:
        json.dump(report, report_file, indent=2, ensure_ascii=False)
        report_file.write("\n")
    return output_path
