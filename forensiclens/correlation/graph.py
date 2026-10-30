"""ForensicLens Evidence Relationship Graph Generator."""

from __future__ import annotations

from typing import Any


class EvidenceGraph:
    """Directed Evidence Provenance & Relationship Graph.

    Models: source evidence -> video -> track -> event -> correlated event -> derived report
    Strictly distinguishes detected facts from inferred associations.
    """

    def __init__(self) -> None:
        self.nodes: dict[str, dict[str, Any]] = {}
        self.edges: list[dict[str, Any]] = []

    def add_node(
        self,
        node_id: str,
        label: str,
        node_type: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if node_id not in self.nodes:
            self.nodes[node_id] = {
                "id": node_id,
                "label": label,
                "type": node_type,
                "metadata": metadata or {},
            }
        else:
            if metadata:
                self.nodes[node_id]["metadata"].update(metadata)

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relationship: str,
        assertion_type: str,  # "detected_fact" or "inferred_association"
        confidence: float | None = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        edge_id = f"edge-{len(self.edges) + 1:06d}"
        self.edges.append({
            "id": edge_id,
            "source": source_id,
            "target": target_id,
            "relationship": relationship,
            "assertion_type": assertion_type,
            "confidence": confidence,
            "metadata": metadata or {},
        })

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": list(self.nodes.values()),
            "edges": self.edges,
            "summary": {
                "detected_facts_count": sum(1 for e in self.edges if e["assertion_type"] == "detected_fact"),
                "inferred_associations_count": sum(1 for e in self.edges if e["assertion_type"] == "inferred_association"),
            },
        }


def build_evidence_graph(
    report_data: dict[str, Any],
    correlations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Construct a full traceable evidence graph from a case report and correlation list."""
    graph = EvidenceGraph()
    case_info = report_data.get("case", {})
    case_id = case_info.get("case_id", "CASE-ROOT")
    case_title = case_info.get("investigation_title", "Forensic Case")

    # 1. Root Case Node
    graph.add_node(
        case_id,
        f"Case: {case_id}",
        "case",
        {
            "title": case_title,
            "icon_type": "case",
            "category": "Case Dossier",
            "stage": 0,
            "status": "ACTIVE_INVESTIGATION",
        },
    )

    # 2. Source Files & Videos
    evidence_files = report_data.get("evidence_files", [])
    videos = report_data.get("video_evidence", {}).get("videos", [])

    for file_record in evidence_files:
        fid = file_record["evidence_id"]
        fname = file_record.get("filename", fid)
        is_img = file_record.get("is_image", False)
        graph.add_node(
            fid,
            fname,
            "source_file",
            {
                "sha256": file_record.get("sha256"),
                "size_bytes": file_record.get("size_bytes"),
                "is_image": is_img,
                "icon_type": "image_evidence" if is_img else "file_evidence",
                "category": "Source Evidence",
                "stage": 1,
            },
        )
        graph.add_edge(case_id, fid, "contains_source_evidence", "detected_fact")

    for vid in videos:
        vid_id = vid["evidence_id"]
        vname = vid.get("filename", vid_id)
        meta = vid.get("video_metadata", {})
        graph.add_node(
            vid_id,
            vname,
            "video_evidence",
            {
                "sha256": vid.get("original_integrity", {}).get("sha256"),
                "fps": meta.get("fps", 30),
                "duration_seconds": meta.get("duration_seconds", 0.0),
                "resolution": f"{meta.get('width', 1920)}x{meta.get('height', 1080)}",
                "relative_path": vid.get("relative_path", ""),
                "icon_type": "video_cctv",
                "category": "Surveillance Feed",
                "stage": 2,
            },
        )
        graph.add_edge(case_id, vid_id, "contains_video_evidence", "detected_fact")

    # 3. Tracks
    tracks = report_data.get("track_summary", [])
    for trk in tracks:
        parent = trk.get("parent_evidence_id", case_id)
        track_id = trk.get("track_id")
        node_track_id = f"track-{parent[3:]}-{track_id}"
        obj_class = trk.get("class", "object")
        icon_type = "person_track" if obj_class == "person" else ("vehicle_track" if obj_class in ("car", "truck", "bus", "vehicle") else "object_track")
        traj = trk.get("bounding_box_trajectory_summary", {})
        direction = traj.get("direction", "stationary")

        graph.add_node(
            node_track_id,
            f"Track {track_id} ({obj_class})",
            "track",
            {
                "parent_evidence_id": parent,
                "track_id": track_id,
                "class": obj_class,
                "duration_seconds": trk.get("duration_seconds"),
                "confidence": trk.get("mean_confidence"),
                "review_priority": trk.get("review_priority", "nominal"),
                "direction": direction,
                "displacement_pixels": traj.get("displacement_pixels", 0.0),
                "entry_edge": trk.get("entry_edge"),
                "exit_edge": trk.get("exit_edge"),
                "icon_type": icon_type,
                "category": "AI Object Track",
                "stage": 3,
            },
        )
        # Tracks are formed via multi-object tracking association -> inferred_association
        graph.add_edge(parent, node_track_id, "tracker_identified_track", "inferred_association", trk.get("mean_confidence"))

    # 4. Forensic Events
    events = report_data.get("forensic_events", [])
    for evt in events:
        eid = evt.get("event_id")
        etype = evt.get("event_type", "event")
        parent = evt.get("parent_evidence_id", case_id)
        assertion = evt.get("assertion_type", "detected_fact")
        track_id = evt.get("track_id")
        prio = evt.get("review_priority", "low")
        anomaly_score = evt.get("anomaly_score", 0.0)

        # Classify icon
        if "entered" in etype or "exited" in etype:
            icon_type = "boundary_event"
        elif "movement" in etype or "displacement" in etype:
            icon_type = "motion_event"
        elif "presence" in etype or "dwell" in etype:
            icon_type = "presence_event"
        elif prio == "high" or anomaly_score > 0.5:
            icon_type = "anomaly_event"
        else:
            icon_type = "forensic_event"

        graph.add_node(
            eid,
            f"Event: {etype}",
            "forensic_event",
            {
                "event_type": etype,
                "timestamp_seconds": evt.get("video_timestamp_seconds", 0.0),
                "explanation": evt.get("explanation"),
                "confidence": evt.get("confidence", 1.0),
                "anomaly_score": anomaly_score,
                "review_priority": prio,
                "parent_evidence_id": parent,
                "track_id": track_id,
                "icon_type": icon_type,
                "category": "Forensic Event",
                "stage": 4,
            },
        )

        if track_id is not None:
            node_track_id = f"track-{parent[3:]}-{track_id}"
            graph.add_edge(node_track_id, eid, f"generated_{etype}", assertion, evt.get("confidence"))
        else:
            graph.add_edge(parent, eid, "occurred_in_video", assertion, evt.get("confidence"))

    # 5. Correlated Events
    if correlations:
        for corr in correlations:
            cid = corr["correlation_id"]
            src_e = corr["source_event_id"]
            tgt_e = corr["target_event_id"]
            rel = corr["relationship_type"]
            score = corr["score"]

            graph.add_node(
                cid,
                f"Correlation: {rel}",
                "correlation_link",
                {
                    "relationship_type": rel,
                    "score": score,
                    "explanation": corr.get("explanation"),
                    "source_event_id": src_e,
                    "target_event_id": tgt_e,
                    "icon_type": "correlation_nexus",
                    "category": "Correlated Intelligence",
                    "stage": 5,
                },
            )
            if src_e in graph.nodes:
                graph.add_edge(src_e, cid, "participates_in_correlation", "inferred_association", score)
            if tgt_e in graph.nodes:
                graph.add_edge(cid, tgt_e, "correlated_with", "inferred_association", score)

    # 6. Derived Report / Artifact Nodes
    report_node_id = "artifact-forensic-report"
    graph.add_node(
        report_node_id,
        "Forensic Case Report",
        "derived_artifact",
        {
            "analysis_timestamp_utc": report_data.get("analysis_timestamp_utc"),
            "tamper_status": report_data.get("integrity_summary", {}).get("tamper_status", "MATCH"),
            "icon_type": "certified_report",
            "category": "Immutable Artifact",
            "stage": 6,
        },
    )
    graph.add_edge(case_id, report_node_id, "compiled_into_report", "detected_fact")

    return graph.to_dict()
