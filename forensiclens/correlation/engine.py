"""ForensicLens Surveillance Event Correlation Engine."""

from __future__ import annotations

from typing import Any
from .topology import CameraTopology


DEFAULT_CORRELATION_CONFIG = {
    "temporal_proximity_window_seconds": 15.0,
    "min_correlation_score": 0.40,
    "max_correlations_per_event": 5,
}


def _get_timestamp(event: dict[str, Any]) -> float:
    t = event.get("video_timestamp_seconds")
    if t is not None:
        try:
            return float(t)
        except (ValueError, TypeError):
            pass
    refs = event.get("frame_references", [])
    if refs and "video_relative_timestamp_seconds" in refs[0]:
        try:
            return float(refs[0]["video_relative_timestamp_seconds"])
        except (ValueError, TypeError):
            pass
    return 0.0


def _get_frame_index(event: dict[str, Any]) -> int | None:
    refs = event.get("frame_references", [])
    if refs and "frame_index" in refs[0]:
        return int(refs[0]["frame_index"])
    return None


class CorrelationEngine:
    """Deterministic correlation engine for multi-camera / intra-video surveillance events."""

    def __init__(self, config: dict[str, Any] | None = None, topology: CameraTopology | None = None) -> None:
        self.config = {**DEFAULT_CORRELATION_CONFIG, **(config or {})}
        self.topology = topology or CameraTopology()

    def correlate_events(
        self,
        forensic_events: list[dict[str, Any]],
        track_summaries: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Evaluate correlations among all forensic events."""
        if not forensic_events:
            return []

        correlations: list[dict[str, Any]] = []
        corr_sequence = 0
        window = float(self.config["temporal_proximity_window_seconds"])
        min_score = float(self.config["min_correlation_score"])

        sorted_events = sorted(forensic_events, key=lambda e: (_get_timestamp(e), e.get("event_id", "")))
        event_count = len(sorted_events)

        # Track summary lookup
        track_map = {}
        for trk in (track_summaries or []):
            key = (trk.get("parent_evidence_id"), trk.get("track_id"))
            track_map[key] = trk

        for i in range(event_count):
            e1 = sorted_events[i]
            t1 = _get_timestamp(e1)
            p1 = e1.get("parent_evidence_id")
            type1 = e1.get("event_type", "")
            track1 = e1.get("track_id")

            matches_for_e1 = 0

            for j in range(i + 1, event_count):
                e2 = sorted_events[j]
                t2 = _get_timestamp(e2)
                p2 = e2.get("parent_evidence_id")
                type2 = e2.get("event_type", "")
                track2 = e2.get("track_id")

                delta_t = t2 - t1
                if delta_t > window:
                    break

                # 1. Evaluate Cross-Camera / Same-Camera relationship
                is_cross_camera = (p1 != p2)
                rel_type: str | None = None
                score = 0.0
                explanation = ""

                if is_cross_camera:
                    # Cross-camera correlation
                    plausible, topo_score = self.topology.is_plausible_transition(str(p1), str(p2), delta_t)
                    if plausible:
                        rel_type = "cross_camera_related_event"
                        proximity_score = max(0.0, 1.0 - (delta_t / window))
                        score = round(0.5 * proximity_score + 0.5 * topo_score, 4)
                        explanation = f"Cross-camera event sequence ({p1} -> {p2}) occurred within {delta_t:.2f}s."
                else:
                    # Same camera correlations
                    if track1 is not None and track1 == track2:
                        if "entered" in type1 and ("exited" in type2 or "movement" in type2):
                            rel_type = "sequential_movement"
                            score = round(max(0.6, 1.0 - (delta_t / (2.0 * window))), 4)
                            explanation = f"Track {track1} progression: '{type1}' followed by '{type2}' over {delta_t:.2f}s."
                        else:
                            rel_type = "same_camera_sequence"
                            score = round(max(0.5, 1.0 - (delta_t / window)), 4)
                            explanation = f"Co-occurring events on Track {track1} ({type1} and {type2}) within {delta_t:.2f}s."
                    elif type1 == "detection_burst" and type2 == "detection_burst":
                        rel_type = "repeated_track_pattern"
                        score = round(max(0.5, 1.0 - (delta_t / window)), 4)
                        explanation = f"Repeated burst pattern observed within {delta_t:.2f}s."
                    else:
                        rel_type = "temporal_proximity"
                        score = round(max(0.4, 1.0 - (delta_t / window)), 4)
                        explanation = f"Surveillance events '{type1}' and '{type2}' co-occurred in camera feed within {delta_t:.2f}s."

                if rel_type and score >= min_score:
                    corr_sequence += 1
                    corr_record = {
                        "correlation_id": f"corr-{corr_sequence:06d}",
                        "source_event_id": e1.get("event_id"),
                        "target_event_id": e2.get("event_id"),
                        "relationship_type": rel_type,
                        "score": score,
                        "explanation": explanation,
                        "assertion_type": "inferred_association",
                        "time_delta_seconds": round(delta_t, 3),
                        "evidence_references": [
                            {
                                "event_id": e1.get("event_id"),
                                "parent_evidence_id": p1,
                                "event_type": type1,
                                "timestamp_seconds": round(t1, 3),
                                "frame_index": _get_frame_index(e1),
                            },
                            {
                                "event_id": e2.get("event_id"),
                                "parent_evidence_id": p2,
                                "event_type": type2,
                                "timestamp_seconds": round(t2, 3),
                                "frame_index": _get_frame_index(e2),
                            },
                        ],
                    }
                    correlations.append(corr_record)
                    matches_for_e1 += 1
                    if matches_for_e1 >= int(self.config["max_correlations_per_event"]):
                        break

        return correlations
