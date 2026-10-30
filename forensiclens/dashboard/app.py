"""ForensicLens Web Application and API Backend for Investigator Dashboard."""

from __future__ import annotations

from datetime import datetime
import json
import threading
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, render_template, request, send_file, Response
from werkzeug.utils import secure_filename
from flask_cors import CORS

from forensiclens.analyzer import build_evidence_report, write_report
from forensiclens.correlation.graph import build_evidence_graph
from forensiclens.query.engine import GroundedQueryEngine
from forensiclens.reporting.generator import generate_html_report, generate_markdown_report
from forensiclens.sanitization import ProtectedEvidenceError, is_path_protected, sanitize_test_file
from forensiclens.case_workflow import CaseWorkspace, authenticity_risk, build_alerts, create_full_frame_private_copy, now_utc, search_tracks
from forensiclens.preservation import verify_evidence
from forensiclens.video_evidence import VIDEO_EXTENSIONS
from forensiclens.usb_monitor import usb_monitor
from forensiclens.live_cctv import live_cctv_engine


def create_app(report_data: dict[str, Any] | None = None, evidence_root: Path | str = "dataset/raw", video_root: Path | str = "dataset/raw/video") -> Flask:
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).parent / "templates"),
        static_folder=str(Path(__file__).parent / "static"),
    )
    CORS(app)

    # In-memory case state
    state: dict[str, Any] = {
        "report": report_data,
        "evidence_root": Path(evidence_root),
        "video_root": Path(video_root),
        "erasure_certificates": [],
        "workspace": CaseWorkspace(Path("reports/case_workspace.json")),
        "rebuild_requested": False,
    }

    def _ensure_report() -> dict[str, Any]:
        if state["report"] is None:
            # Reuse only a completed forensic-analysis report.  The reports
            # directory also contains workspace metadata and evidence-only
            # exports, neither of which can power the video marker UI.
            reports_dir = Path("reports")
            preferred_reports = sorted(
                reports_dir.glob("forensic_case_report_*.json"),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
            fallback_reports = sorted(
                reports_dir.glob("evidence_report_*.json"),
                key=lambda path: path.stat().st_mtime,
                reverse=True,
            )
            for candidate in ([] if state["rebuild_requested"] else [*preferred_reports, *fallback_reports]):
                try:
                    with candidate.open("r", encoding="utf-8") as report_file:
                        candidate_data = json.load(report_file)
                    intelligence = candidate_data.get("video_events", {})
                    if intelligence.get("status") == "completed" and candidate_data.get("forensic_events"):
                        state["report"] = candidate_data
                        break
                except Exception:
                    continue

            if state["report"] is None:
                state["report"] = build_evidence_report(
                    evidence_root=state["evidence_root"],
                    video_root=state["video_root"],
                    enable_video_intelligence=True,
                    case_id="CASE-2026-001",
                    investigation_title="ForensicLens SIH PS 26150 Case",
                )
                state["rebuild_requested"] = False
        return state["report"]

    def _rebuild_report() -> dict[str, Any]:
        """Analyze every video in the case directory and persist only derived report data."""
        state["rebuild_requested"] = True
        state["report"] = build_evidence_report(
            evidence_root=state["evidence_root"],
            video_root=state["video_root"],
            enable_video_intelligence=True,
            case_id="CASE-2026-001",
            investigation_title="ForensicLens Multi-Feed CCTV Investigation",
        )
        write_report(state["report"], Path("reports/forensic_case_report_CURRENT.json"))
        state["rebuild_requested"] = False
        return state["report"]

    def _enrich_live_state(report: dict[str, Any]) -> dict[str, Any]:
        workspace = state["workspace"].data
        report["investigator_workspace"] = workspace
        report["workflow"] = workspace.get("workflow", {})
        report["alerts"] = workspace.get("alerts", [])
        report["authenticity_screening"] = workspace.get("authenticity_screening", [])
        for event in report.get("forensic_events", []):
            event["investigator_review"] = workspace.get("reviews", {}).get(event.get("event_id"))
        return report

    @app.route("/")
    def index() -> str:
        _ensure_report()
        return render_template("index.html")

    @app.route("/api/case", methods=["GET"])
    def get_case_data() -> Any:
        report = _ensure_report()
        # Attach any live erasure certificates
        report["erasure_certificates"] = state["erasure_certificates"]
        return jsonify(_enrich_live_state(report))

    @app.route("/api/videos/upload", methods=["POST"])
    def upload_videos() -> Any:
        """Safely intake new video evidence as separate files; existing evidence is never overwritten."""
        files = request.files.getlist("videos")
        if not files:
            return jsonify({"error": "Select one or more video files."}), 400
        intake_dir = state["video_root"].resolve()
        intake_dir.mkdir(parents=True, exist_ok=True)
        added: list[dict[str, Any]] = []
        for incoming in files:
            filename = secure_filename(incoming.filename or "")
            if not filename or Path(filename).suffix.lower() not in VIDEO_EXTENSIONS:
                return jsonify({"error": f"Unsupported video: {incoming.filename}"}), 400
            destination = intake_dir / filename
            if destination.exists():
                return jsonify({"error": f"A video named {filename} already exists. Rename it before upload to preserve evidence provenance."}), 409
            incoming.save(destination)
            from forensiclens.preservation import capture_integrity
            integrity = capture_integrity(destination)
            added.append({"filename": filename, "size_bytes": integrity.get("size_bytes"), "sha256": integrity.get("sha256"), "status": "intake_hash_recorded"})
        state["report"] = None
        state["rebuild_requested"] = True
        return jsonify({"status": "uploaded", "videos": added, "next_step": "Run multi-feed analysis to detect events across all videos."}), 201

    @app.route("/api/case/reanalyze", methods=["POST"])
    def reanalyze_case() -> Any:
        try:
            return jsonify(_enrich_live_state(_rebuild_report()))
        except Exception as error:
            return jsonify({"error": f"Multi-feed analysis failed: {error}"}), 500

    @app.route("/api/workflow/run", methods=["POST"])
    def run_investigation_workflow() -> Any:
        """One-click demo flow: verify evidence, screen videos, create reviewable alerts."""
        try:
            report = _ensure_report()
            workspace = state["workspace"]
            verification = []
            for item in report.get("video_evidence", {}).get("videos", []):
                source = state["video_root"] / item["relative_path"]
                if source.is_file():
                    v_res = verify_evidence(source, item.get("original_integrity", {}).get("sha256"))
                    verification.append({"evidence_id": item["evidence_id"], **v_res})
            screening = [authenticity_risk(video, state["video_root"]) for video in report.get("video_evidence", {}).get("videos", [])]
            workspace.data["authenticity_screening"] = screening
            workspace.data["alerts"] = build_alerts(report)
            workspace.data["workflow"] = {"status": "ready_for_investigator_review", "last_run_utc": now_utc(), "steps": [
                {"name": "Evidence hash verification", "status": "completed", "detail": verification},
                {"name": "AI event analysis", "status": report.get("video_events", {}).get("status", "available")},
                {"name": "Authenticity risk screening", "status": "completed"},
                {"name": "Investigator review", "status": "awaiting_review"},
                {"name": "Signed report export", "status": "available"},
            ]}
            workspace.save()
            return jsonify(_enrich_live_state(report))
        except Exception as error:
            return jsonify({"error": f"Investigation workflow failed: {error}"}), 500

    @app.route("/api/reviews/<event_id>", methods=["POST"])
    def save_review(event_id: str) -> Any:
        payload = request.get_json(silent=True) or {}
        decision = payload.get("decision")
        if decision not in {"confirmed", "rejected", "needs_review"}:
            return jsonify({"error": "decision must be confirmed, rejected, or needs_review"}), 400
        return jsonify(state["workspace"].review(event_id, decision, str(payload.get("reason", ""))[:500], str(payload.get("investigator", "Investigator"))[:100]))

    @app.route("/api/notes", methods=["POST"])
    def add_note() -> Any:
        payload = request.get_json(silent=True) or {}
        body = str(payload.get("body", "")).strip()
        if not body:
            return jsonify({"error": "A note is required"}), 400
        return jsonify(state["workspace"].add_note(body[:1000], str(payload.get("author", "Investigator"))[:100], payload.get("target_id")))

    @app.route("/api/tracks/search", methods=["GET"])
    def find_tracks() -> Any:
        report = _ensure_report()
        args = request.args
        parse = lambda value: float(value) if value not in (None, "") else None
        try:
            matches = search_tracks(report, args.get("class") or None, parse(args.get("start")), parse(args.get("end")))
        except ValueError:
            return jsonify({"error": "start and end must be numeric seconds"}), 400
        return jsonify({"matches": matches, "disclaimer": "Matches are local tracker candidates based on class and time. They do not identify a person or establish cross-camera identity."})

    @app.route("/api/privacy/export", methods=["POST"])
    def privacy_export() -> Any:
        report = _ensure_report()
        video = report.get("video_evidence", {}).get("videos", [None])[0]
        if not video:
            return jsonify({"error": "No video evidence is available."}), 400
        try:
            derived = create_full_frame_private_copy(video, state["video_root"], Path("reports/privacy_exports"))
            state["workspace"].data.setdefault("privacy_exports", []).append(derived)
            state["workspace"].save()
            return jsonify(derived)
        except Exception as error:
            return jsonify({"error": str(error)}), 400

    @app.route("/api/query", methods=["POST"])
    def query_case() -> Any:
        report = _ensure_report()
        payload = request.get_json(silent=True) or {}
        question = payload.get("query", "")
        if not question:
            return jsonify({"error": "No query provided"}), 400

        engine = GroundedQueryEngine(report)
        response = engine.query(question)
        return jsonify(response)

    @app.route("/api/sanitize", methods=["POST"])
    def sanitize_copy() -> Any:
        payload = request.get_json(silent=True) or {}
        target_path_str = payload.get("target_path", "").strip()
        method = payload.get("method", "NIST_SP_800_88_CLEAR")
        operator_id = payload.get("operator_id", "ForensicInvestigator_UI")
        create_sample = payload.get("create_sample_if_missing", False)

        if not target_path_str:
            return jsonify({"error": "No target path provided"}), 400

        target_path = Path(target_path_str)

        # Helper for UI testing: safely create a scratch test file if requested
        if create_sample and not target_path.exists():
            scratch_dir = Path("scratch_sanitization_test")
            scratch_dir.mkdir(parents=True, exist_ok=True)
            target_path = scratch_dir / "safe_test_evidence_copy.tmp"
            target_path.write_bytes(b"TEMPORARY_TEST_EVIDENCE_COPY_CREATED_FOR_UI_SANITIZATION_DEMO")

        try:
            cert = sanitize_test_file(
                target_path,
                method=method,
                operator_id=operator_id,
                unlink_after_sanitization=True,
            )
            cert_dict = cert.to_dict()
            state["erasure_certificates"].append(cert_dict)
            return jsonify({
                "status": "success",
                "certificate": cert_dict,
            })
        except ProtectedEvidenceError as pe:
            return jsonify({
                "status": "rejected_protected",
                "error": str(pe),
                "message": "PROTECTED EVIDENCE: ForensicLens refused to sanitize source evidence.",
            }), 403
        except Exception as e:
            return jsonify({"status": "error", "error": str(e)}), 400

    @app.route("/api/video/<path:relative_path>")
    def stream_video(relative_path: str) -> Any:
        video_root = state["video_root"].resolve()
        path = (video_root / relative_path).resolve()
        if not path.is_file():
            # Check dataset/raw/video fallback
            alt = (Path("dataset/raw/video") / relative_path).resolve()
            if alt.is_file():
                path = alt
            else:
                return jsonify({"error": f"Video not found: {relative_path}"}), 404

        return send_file(path, mimetype="video/mp4", conditional=True)

    @app.route("/api/report/export/<fmt>", methods=["GET"])
    def export_report(fmt: str) -> Any:
        report = _enrich_live_state(_ensure_report())
        case_id = report.get("case", {}).get("case_id", "CASE-2026-001")

        if fmt == "json":
            return Response(
                json.dumps(report, indent=2),
                mimetype="application/json",
                headers={"Content-Disposition": f"attachment;filename=report_{case_id}.json"},
            )
        elif fmt == "markdown":
            md = generate_markdown_report(report)
            return Response(
                md,
                mimetype="text/markdown",
                headers={"Content-Disposition": f"attachment;filename=report_{case_id}.md"},
            )
        elif fmt == "html":
            html = generate_html_report(report)
            return Response(
                html,
                mimetype="text/html",
                headers={"Content-Disposition": f"attachment;filename=report_{case_id}.html"},
            )
        return jsonify({"error": "Unsupported format"}), 400

    # =========================================================================
    # LIVE USB & REMOVABLE STORAGE FORENSIC API ENDPOINTS
    # =========================================================================

    @app.route("/api/usb/status", methods=["GET"])
    def get_usb_status() -> Any:
        """Return live connected USB devices and file monitoring metrics."""
        return jsonify(usb_monitor.get_status())

    @app.route("/api/usb/events", methods=["GET"])
    def get_usb_events() -> Any:
        """Return real-time USB plug/unplug and file creation/edit/deletion events."""
        limit = request.args.get("limit", default=200, type=int)
        since_id = request.args.get("since_id", default=None, type=str)
        event_type = request.args.get("event_type", default=None, type=str)
        events = usb_monitor.get_events(limit=limit, since_id=since_id, event_type=event_type)
        return jsonify({
            "status": "success",
            "count": len(events),
            "events": events,
            "monitor": usb_monitor.get_status(),
        })

    @app.route("/api/usb/monitor/toggle", methods=["POST"])
    def toggle_usb_monitor() -> Any:
        """Toggle background USB monitoring or add custom directory to watch."""
        payload = request.get_json(silent=True) or {}
        action = payload.get("action", "toggle")
        custom_path = payload.get("custom_path", "").strip()

        if action == "start":
            usb_monitor.start()
        elif action == "stop":
            usb_monitor.stop()
        elif action == "add_custom" and custom_path:
            added = usb_monitor.add_custom_watch_path(custom_path)
            return jsonify({"status": "success", "message": f"Added custom watch path: {added}", "monitor": usb_monitor.get_status()})
        elif action == "remove_custom" and custom_path:
            usb_monitor.remove_custom_watch_path(custom_path)
            return jsonify({"status": "success", "message": f"Removed custom watch path: {custom_path}", "monitor": usb_monitor.get_status()})
        else:
            if usb_monitor.is_running:
                usb_monitor.stop()
            else:
                usb_monitor.start()

        return jsonify({"status": "success", "is_monitoring": usb_monitor.is_running, "monitor": usb_monitor.get_status()})

    @app.route("/api/usb/simulate", methods=["POST"])
    def simulate_usb_activity() -> Any:
        """Simulate realistic USB insertion, file modifications/deletions, and safe removal."""
        result = usb_monitor.simulate_demo_activity()
        return jsonify(result)

    @app.route("/api/usb/export/<fmt>", methods=["GET"])
    def export_usb_report(fmt: str) -> Any:
        """Export USB forensic audit trail to JSON, Markdown, or CSV."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if fmt == "json":
            return Response(
                usb_monitor.export_report_json(),
                mimetype="application/json",
                headers={"Content-Disposition": f"attachment;filename=usb_forensic_audit_{timestamp}.json"},
            )
        elif fmt == "markdown" or fmt == "md":
            return Response(
                usb_monitor.export_report_markdown(),
                mimetype="text/markdown",
                headers={"Content-Disposition": f"attachment;filename=usb_forensic_audit_{timestamp}.md"},
            )
        elif fmt == "csv":
            return Response(
                usb_monitor.export_report_csv(),
                mimetype="text/csv",
                headers={"Content-Disposition": f"attachment;filename=usb_forensic_audit_{timestamp}.csv"},
            )
        return jsonify({"error": "Unsupported format. Use json, markdown, or csv."}), 400

    # =========================================================================
    # LIVE CCTV + REAL-TIME THREAT DETECTION (independent of recorded VIRAT)
    # =========================================================================

    @app.route("/api/live/status", methods=["GET"])
    def live_cctv_status() -> Any:
        return jsonify(live_cctv_engine.status())

    @app.route("/api/live/start", methods=["POST"])
    def live_cctv_start() -> Any:
        try:
            return jsonify(live_cctv_engine.start())
        except Exception as error:
            return jsonify({"error": str(error), **live_cctv_engine.status()}), 500

    @app.route("/api/live/stop", methods=["POST"])
    def live_cctv_stop() -> Any:
        return jsonify(live_cctv_engine.stop())

    @app.route("/api/live/clear", methods=["POST"])
    def live_cctv_clear() -> Any:
        return jsonify(live_cctv_engine.clear_alerts())

    @app.route("/api/live/capture", methods=["POST"])
    def live_cctv_capture() -> Any:
        try:
            record = live_cctv_engine.capture_evidence(event_type="Manual Capture", severity="MEDIUM")
            return jsonify({"status": "captured", "evidence": record, **live_cctv_engine.status()}), 201
        except Exception as error:
            return jsonify({"error": str(error), **live_cctv_engine.status()}), 400

    @app.route("/api/live/stream")
    def live_cctv_stream() -> Any:
        return Response(
            live_cctv_engine.mjpeg_generator(),
            mimetype="multipart/x-mixed-replace; boundary=frame",
            headers={"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.route("/api/live/evidence/<evidence_id>/image")
    def live_cctv_evidence_image(evidence_id: str) -> Any:
        from pathlib import Path as _Path
        safe_id = "".join(ch for ch in evidence_id if ch.isalnum() or ch in {"-", "_"})
        path = _Path("reports/live_evidence") / f"{safe_id}.jpg"
        if not path.is_file():
            return jsonify({"error": "Evidence image not found"}), 404
        return send_file(path, mimetype="image/jpeg")

    # Automatically start USB monitoring when app is created
    usb_monitor.start()

    def _prepare_live_models() -> None:
        try:
            live_cctv_engine.prepare_models()
        except Exception:
            pass

    threading.Thread(target=_prepare_live_models, name="live-cctv-models", daemon=True).start()

    return app
