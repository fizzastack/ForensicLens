"""Generate a read-only forensic evidence report."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from forensiclens.analyzer import build_evidence_report, write_report
from forensiclens.reporting.generator import export_standardized_reports


def main() -> None:
    parser = argparse.ArgumentParser(description="Analyze evidence files and write a standardized forensic report.")
    parser.add_argument("source", nargs="?", type=Path, default=Path("dataset/raw"))
    parser.add_argument("--video-source", type=Path, default=Path("dataset/raw/video"), help="Read-only video evidence directory.")
    parser.add_argument("--video-intelligence", action="store_true", help="Run pretrained detection, tracking, and frame-change analysis.")
    parser.add_argument("--intelligence-stride", type=int, default=5, help="Analyze every Nth frame when video intelligence is enabled.")
    parser.add_argument("--intelligence-confidence", type=float, default=0.25, help="Detection confidence threshold.")
    parser.add_argument("--prolonged-presence-seconds", type=float, default=10.0, help="Visible-duration threshold for review events.")
    parser.add_argument("--movement-displacement-pixels", type=float, default=60.0, help="Centroid displacement threshold for movement events.")
    parser.add_argument("--case-id", default="CASE-2026-001", help="Case identifier for the registry and chain of custody.")
    parser.add_argument("--investigation-title", default="ForensicLens Digital Evidence Analysis", help="Investigation title for the case report.")
    parser.add_argument("--output", type=Path, help="Path for the primary JSON report.")
    parser.add_argument("--export-all", action="store_true", help="Export Markdown and HTML reports alongside JSON.")
    args = parser.parse_args()

    timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output = args.output or Path("reports") / f"evidence_report_{timestamp}.json"
    report = build_evidence_report(
        evidence_root=args.source,
        video_root=args.video_source,
        enable_video_intelligence=args.video_intelligence,
        video_intelligence_config={"sampling_stride_frames": args.intelligence_stride, "confidence_threshold": args.intelligence_confidence},
        forensic_event_config={"prolonged_presence_seconds": args.prolonged_presence_seconds, "movement_displacement_pixels": args.movement_displacement_pixels},
        case_id=args.case_id,
        investigation_title=args.investigation_title,
    )
    report_path = write_report(report, output)
    print(f"Evidence report written to: {report_path}")

    if args.export_all:
        paths = export_standardized_reports(report, output_dir=output.parent)
        print(f"  > Standardized Markdown: {paths['markdown']}")
        print(f"  > Standardized HTML:     {paths['html']}")


if __name__ == "__main__":
    main()
