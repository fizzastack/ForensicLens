"""Deterministic aggregation of video detections into forensic review events."""

from __future__ import annotations

from collections import Counter, defaultdict
from math import atan2, degrees, hypot
from statistics import mean
from typing import Any


AGGREGATION_VERSION = "1.0"
DEFAULT_CONFIG = {
    "prolonged_presence_seconds": 10.0,
    "movement_displacement_pixels": 60.0,
    "boundary_margin_ratio": 0.05,
    "multiple_object_count": 2,
    "event_window_seconds": 5.0,
    "detection_burst_count": 8,
}
VEHICLE_CLASSES = {"bicycle", "car", "motorcycle", "bus", "truck"}


def _event_id(parent: str, event_type: str, frame: int, sequence: int) -> str:
    return f"fe-{parent[3:]}-{event_type}-{frame:06d}-{sequence:04d}"


def _frame_ref(frame_index: int, timestamp: float) -> dict[str, Any]:
    return {"frame_index": frame_index, "video_relative_timestamp_seconds": timestamp}


def _edge(box: list[float], width: int | None, height: int | None, margin_ratio: float) -> str | None:
    if not width or not height:
        return None
    margin_x, margin_y = width * margin_ratio, height * margin_ratio
    left, top, right, bottom = box
    if left <= margin_x:
        return "left"
    if right >= width - margin_x:
        return "right"
    if top <= margin_y:
        return "top"
    if bottom >= height - margin_y:
        return "bottom"
    return None


def _direction(dx: float, dy: float, threshold: float) -> str | None:
    if hypot(dx, dy) < threshold:
        return None
    angle = degrees(atan2(-dy, dx))
    labels = ["east", "north-east", "north", "north-west", "west", "south-west", "south", "south-east"]
    return labels[int((angle + 22.5) % 360 // 45)]


def _timeline_event(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": f"{event['video_timestamp_seconds']:.6f}",
        "timestamp_kind": "video_relative_seconds",
        "event_type": event["event_type"],
        "evidence_file": event.get("evidence_file", event["parent_evidence_id"]),
        "parent_evidence_id": event["parent_evidence_id"],
        "description": event["explanation"],
        "source": event["source"],
        "availability": event["availability"],
    }


def _base_event(
    parent: str, source_sha256: str | None, event_type: str, assertion_type: str, timestamp: float,
    frame_references: list[dict[str, Any]], source: str, confidence: float | None, explanation: str,
    sequence: int, availability: str = "available", track_id: int | None = None,
) -> dict[str, Any]:
    event = {
        "event_id": _event_id(parent, event_type, frame_references[0]["frame_index"], sequence),
        "parent_evidence_id": parent,
        "source_sha256": source_sha256,
        "event_type": event_type,
        "assertion_type": assertion_type,
        "video_timestamp_seconds": timestamp,
        "frame_references": frame_references,
        "source": source,
        "confidence": confidence,
        "explanation": explanation,
        "availability": availability,
    }
    if track_id is not None:
        event["track_id"] = track_id
    return event


def _tracks_from_detections(raw_events: list[dict[str, Any]]) -> dict[tuple[str, int], list[dict[str, Any]]]:
    tracks: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for event in raw_events:
        if event.get("event_type") != "object_detected" or event.get("assertion_type") != "detected_fact":
            continue
        object_data = event.get("object", {})
        track_id = object_data.get("track_id")
        if track_id is None:
            continue
        if not object_data.get("bounding_box_xyxy"):
            continue
        tracks[(event["parent_evidence_id"], int(track_id))].append(event)
    return tracks


def _track_summary(
    parent: str, track_id: int, detections: list[dict[str, Any]], dimensions: dict[str, Any], config: dict[str, Any], source_sha256: str | None,
) -> dict[str, Any]:
    ordered = sorted(detections, key=lambda item: (item["frame_reference"]["frame_index"], item["video_timestamp_seconds"]))
    object_classes = [item["object"]["class"] for item in ordered]
    object_class = Counter(object_classes).most_common(1)[0][0]
    confidences = [item["object"]["confidence"] for item in ordered if item["object"].get("confidence") is not None]
    first, last = ordered[0], ordered[-1]
    first_box, last_box = first["object"]["bounding_box_xyxy"], last["object"]["bounding_box_xyxy"]
    first_centroid = ((first_box[0] + first_box[2]) / 2, (first_box[1] + first_box[3]) / 2)
    last_centroid = ((last_box[0] + last_box[2]) / 2, (last_box[1] + last_box[3]) / 2)
    dx, dy = last_centroid[0] - first_centroid[0], last_centroid[1] - first_centroid[1]
    displacement = hypot(dx, dy)
    duration = max(0.0, last["video_timestamp_seconds"] - first["video_timestamp_seconds"])
    width, height = dimensions.get("width"), dimensions.get("height")
    return {
        "parent_evidence_id": parent,
        "source_sha256": source_sha256,
        "track_id": track_id,
        "class": object_class,
        "first_frame": first["frame_reference"]["frame_index"],
        "last_frame": last["frame_reference"]["frame_index"],
        "first_timestamp_seconds": first["video_timestamp_seconds"],
        "last_timestamp_seconds": last["video_timestamp_seconds"],
        "duration_seconds": duration,
        "mean_confidence": mean(confidences) if confidences else None,
        "max_confidence": max(confidences) if confidences else None,
        "number_of_detections": len(ordered),
        "bounding_box_trajectory_summary": {
            "first_box_xyxy": first_box, "last_box_xyxy": last_box,
            "first_centroid_xy": [round(value, 2) for value in first_centroid],
            "last_centroid_xy": [round(value, 2) for value in last_centroid],
            "displacement_pixels": round(displacement, 2),
            "direction": _direction(dx, dy, config["movement_displacement_pixels"]),
        },
        "entry_edge": _edge(first_box, width, height, config["boundary_margin_ratio"]),
        "exit_edge": _edge(last_box, width, height, config["boundary_margin_ratio"]),
        "_detections": ordered,
    }


def aggregate_forensic_events(video_events: dict[str, Any], video_evidence: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
    """Aggregate only model detections into transparent, evidence-backed review events."""
    settings = {**DEFAULT_CONFIG, **(config or {})}
    raw_events = video_events.get("events", [])
    videos = {video["evidence_id"]: video for video in video_evidence.get("videos", [])}
    tracks = _tracks_from_detections(raw_events)
    summaries: list[dict[str, Any]] = []
    forensic_events: list[dict[str, Any]] = []
    sequence = 0
    frame_objects: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)

    for (parent, track_id), detections in sorted(tracks.items()):
        video = videos.get(parent, {})
        metadata = video.get("video_metadata", {})
        source_sha = video.get("original_integrity", {}).get("sha256")
        summary = _track_summary(parent, track_id, detections, metadata, settings, source_sha)
        summaries.append(summary)
        first, last = summary["_detections"][0], summary["_detections"][-1]
        all_frames = [event["frame_reference"]["frame_index"] for event in raw_events if event.get("parent_evidence_id") == parent and event.get("event_type") == "object_detected"]
        if summary["entry_edge"] and summary["first_frame"] > min(all_frames, default=summary["first_frame"]):
            sequence += 1
            kind = "person_entered" if summary["class"] == "person" else "vehicle_entered" if summary["class"] in VEHICLE_CLASSES else None
            if kind:
                forensic_events.append(_base_event(parent, source_sha, kind, "inferred_association", summary["first_timestamp_seconds"], [_frame_ref(summary["first_frame"], summary["first_timestamp_seconds"])], "boundary_position_rule", summary["mean_confidence"], f"Track first appeared near the {summary['entry_edge']} frame boundary; this infers visible-frame entry only, not real-world entry.", sequence, track_id=track_id))
        if summary["exit_edge"] and summary["last_frame"] < max(all_frames, default=summary["last_frame"]):
            sequence += 1
            kind = "person_exited" if summary["class"] == "person" else "vehicle_exited" if summary["class"] in VEHICLE_CLASSES else None
            if kind:
                forensic_events.append(_base_event(parent, source_sha, kind, "inferred_association", summary["last_timestamp_seconds"], [_frame_ref(summary["last_frame"], summary["last_timestamp_seconds"])], "boundary_position_rule", summary["mean_confidence"], f"Track last appeared near the {summary['exit_edge']} frame boundary; this infers visible-frame exit only, not real-world exit.", sequence, track_id=track_id))
        if summary["duration_seconds"] >= settings["prolonged_presence_seconds"]:
            sequence += 1
            forensic_events.append(_base_event(parent, source_sha, "prolonged_presence", "detected_fact", summary["last_timestamp_seconds"], [_frame_ref(summary["first_frame"], summary["first_timestamp_seconds"]), _frame_ref(summary["last_frame"], summary["last_timestamp_seconds"])], "track_lifecycle", summary["mean_confidence"], f"Track was detected for {summary['duration_seconds']:.2f}s, meeting the {settings['prolonged_presence_seconds']:.2f}s threshold.", sequence, track_id=track_id))
        displacement = summary["bounding_box_trajectory_summary"]["displacement_pixels"]
        if displacement >= settings["movement_displacement_pixels"]:
            sequence += 1
            speed = displacement / summary["duration_seconds"] if summary["duration_seconds"] > 0 else None
            movement = _base_event(parent, source_sha, "movement_detected", "detected_fact", summary["last_timestamp_seconds"], [_frame_ref(summary["first_frame"], summary["first_timestamp_seconds"]), _frame_ref(summary["last_frame"], summary["last_timestamp_seconds"])], "track_centroid_displacement", summary["mean_confidence"], f"Track centroid displacement of {displacement:.2f}px met the {settings['movement_displacement_pixels']:.2f}px threshold.", sequence, track_id=track_id)
            movement["movement"] = {"displacement_pixels": displacement, "direction": summary["bounding_box_trajectory_summary"]["direction"], "speed_pixels_per_second": speed, "frames_used": [summary["first_frame"], summary["last_frame"]], "threshold_pixels": settings["movement_displacement_pixels"]}
            forensic_events.append(movement)
        for detection in summary["_detections"]:
            frame_objects[(parent, detection["frame_reference"]["frame_index"])].append(detection)

    # One event per contiguous high-density sampled-frame window, not one per detection.
    for parent in sorted({key[0] for key in frame_objects}):
        video = videos.get(parent, {})
        source_sha = video.get("original_integrity", {}).get("sha256")
        qualifying = [(frame, objects) for (item_parent, frame), objects in sorted(frame_objects.items()) if item_parent == parent and len(objects) >= settings["multiple_object_count"]]
        if qualifying:
            frame, objects = qualifying[0]
            timestamp = objects[0]["video_timestamp_seconds"]
            sequence += 1
            forensic_events.append(_base_event(parent, source_sha, "multiple_objects_present", "detected_fact", timestamp, [_frame_ref(frame, timestamp)], "detection_count", mean([item["object"]["confidence"] for item in objects]), f"{len(objects)} detected objects met the simultaneous-object threshold of {settings['multiple_object_count']}.", sequence))

        detections = [event for event in raw_events if event.get("parent_evidence_id") == parent and event.get("event_type") == "object_detected"]
        if detections:
            first_timestamp = min(event["video_timestamp_seconds"] for event in detections)
            window = [event for event in detections if event["video_timestamp_seconds"] <= first_timestamp + settings["event_window_seconds"]]
            if len(window) >= settings["detection_burst_count"]:
                sequence += 1
                forensic_events.append(_base_event(parent, source_sha, "detection_burst", "detected_fact", first_timestamp, [_frame_ref(event["frame_reference"]["frame_index"], event["video_timestamp_seconds"]) for event in window], "detection_frequency", mean([event["object"]["confidence"] for event in window]), f"{len(window)} detections occurred within {settings['event_window_seconds']:.2f}s, meeting the burst threshold of {settings['detection_burst_count']}.", sequence))

    features: list[dict[str, Any]] = []
    for index, summary in enumerate(sorted(summaries, key=lambda item: (item["parent_evidence_id"], item["first_frame"], item["track_id"]))):
        features.append({
            "feature_id": f"track-feature-{summary['parent_evidence_id'][3:]}-{summary['track_id']}", "feature_kind": "track",
            "parent_evidence_id": summary["parent_evidence_id"], "track_id": summary["track_id"], "object_class": summary["class"],
            "duration_seconds": summary["duration_seconds"], "mean_confidence": summary["mean_confidence"], "max_confidence": summary["max_confidence"],
            "detection_count": summary["number_of_detections"], "displacement_pixels": summary["bounding_box_trajectory_summary"]["displacement_pixels"],
            "mean_velocity_pixels_per_second": (summary["bounding_box_trajectory_summary"]["displacement_pixels"] / summary["duration_seconds"] if summary["duration_seconds"] else None),
            "entry_edge": summary["entry_edge"], "exit_edge": summary["exit_edge"], "time_of_day": None,
            "object_count_in_window": summary["number_of_detections"], "event_frequency_in_window": summary["number_of_detections"] / max(summary["duration_seconds"], 1.0), "sequence_position": index,
        })
    for index, event in enumerate(sorted(forensic_events, key=lambda item: (item["parent_evidence_id"], item["video_timestamp_seconds"], item["event_id"]))):
        features.append({"feature_id": f"event-feature-{event['event_id']}", "feature_kind": "event", "parent_evidence_id": event["parent_evidence_id"], "event_type": event["event_type"], "confidence": event["confidence"], "sequence_position": index, "time_of_day": None, "object_count_in_window": len(event["frame_references"]), "event_frequency_in_window": 1.0 / settings["event_window_seconds"]})

    triage_items: list[dict[str, Any]] = []
    events_by_track: dict[tuple[str, int], list[dict[str, Any]]] = defaultdict(list)
    for event in forensic_events:
        if "track_id" in event:
            events_by_track[(event["parent_evidence_id"], event["track_id"])].append(event)
    for summary in summaries:
        factors: list[str] = []
        score = 0
        if summary["duration_seconds"] >= settings["prolonged_presence_seconds"]:
            score += 35; factors.append("prolonged visible presence")
        if summary["bounding_box_trajectory_summary"]["displacement_pixels"] >= settings["movement_displacement_pixels"]:
            score += 25; factors.append("high centroid displacement")
        if len(events_by_track[(summary["parent_evidence_id"], summary["track_id"])]) >= 2:
            score += 15; factors.append("multiple review events for this local track")
        if summary["number_of_detections"] >= settings["detection_burst_count"]:
            score += 10; factors.append("repeated detection across sampled frames")
        triage_items.append({"parent_evidence_id": summary["parent_evidence_id"], "track_id": summary["track_id"], "triage_score": min(score, 100), "review_priority": "high" if score >= 50 else "medium" if score >= 25 else "low", "explanation": factors or ["No configured triage factor was met."]})

    forensic_events.sort(key=lambda item: (item["parent_evidence_id"], item["video_timestamp_seconds"], item["event_id"]))
    clean_summaries = [{key: value for key, value in summary.items() if key != "_detections"} for summary in summaries]
    return {
        "aggregation_version": AGGREGATION_VERSION,
        "reproducibility_configuration": settings,
        "track_summary": clean_summaries,
        "forensic_events": forensic_events,
        "forensic_features": features,
        "triage_summary": {"items": triage_items, "high_priority_count": sum(item["review_priority"] == "high" for item in triage_items), "medium_priority_count": sum(item["review_priority"] == "medium" for item in triage_items), "low_priority_count": sum(item["review_priority"] == "low" for item in triage_items)},
        "timeline_events": [_timeline_event(event) for event in forensic_events],
        "errors": [],
    }
