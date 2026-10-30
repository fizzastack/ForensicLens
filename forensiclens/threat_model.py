"""One-time local download and inspection of the dedicated threat YOLOv8 model."""

from __future__ import annotations

import json
import shutil
import urllib.request
from pathlib import Path
from typing import Any

THREAT_MODEL_PATH = Path("models/threat_detection/best.pt")
THREAT_CLASSES_PATH = Path("models/threat_detection/classes.json")
THREAT_SOURCE_MARKER = Path("models/threat_detection/source.json")

# Public YOLOv8n threat weights. Actual class names are read from the loaded model.
THREAT_MODEL_SOURCES = [
    {
        "repo_id": "Subh775/Threat-Detection-YOLOv8n",
        "filename": "weights/best.pt",
        "url": "https://huggingface.co/Subh775/Threat-Detection-YOLOv8n/resolve/main/weights/best.pt",
    },
    {
        "repo_id": "SyncRobotic/weapon-detection-yolov8n-v2",
        "filename": "weights/best.pt",
        "url": "https://huggingface.co/SyncRobotic/weapon-detection-yolov8n-v2/resolve/main/weights/best.pt",
    },
]


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _download_with_huggingface(repo_id: str, filename: str, destination: Path) -> bool:
    try:
        from huggingface_hub import hf_hub_download
    except ImportError:
        return False
    try:
        cached = hf_hub_download(repo_id=repo_id, filename=filename)
        shutil.copy2(cached, destination)
        return destination.is_file() and destination.stat().st_size > 1024
    except Exception:
        return False


def _download_with_urllib(url: str, destination: Path) -> bool:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "ForensicLens-LiveCCTV/1.0"})
        with urllib.request.urlopen(request, timeout=120) as response:
            data = response.read()
        if len(data) < 1024:
            return False
        destination.write_bytes(data)
        return True
    except Exception:
        return False


def ensure_threat_model(path: Path | str = THREAT_MODEL_PATH) -> dict[str, Any]:
    """Download the threat model once if missing, then return local path metadata."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_file() and destination.stat().st_size > 1024:
        source = {}
        if THREAT_SOURCE_MARKER.is_file():
            try:
                source = json.loads(THREAT_SOURCE_MARKER.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                source = {}
        return {
            "path": str(destination.resolve()),
            "downloaded": False,
            "reused_local_file": True,
            "source": source,
        }

    errors: list[str] = []
    for source in THREAT_MODEL_SOURCES:
        if _download_with_huggingface(source["repo_id"], source["filename"], destination) or _download_with_urllib(source["url"], destination):
            marker = {"repo_id": source["repo_id"], "filename": source["filename"], "url": source["url"]}
            _write_json(THREAT_SOURCE_MARKER, marker)
            return {
                "path": str(destination.resolve()),
                "downloaded": True,
                "reused_local_file": False,
                "source": marker,
            }
        errors.append(f"{source['repo_id']} unavailable")

    raise FileNotFoundError(
        "Unable to download a threat-detection YOLOv8 model. "
        + "; ".join(errors)
    )


def inspect_threat_classes(model: Any) -> list[str]:
    """Return the class names actually stored on the loaded Ultralytics model."""
    names = getattr(model, "names", {}) or {}
    if isinstance(names, dict):
        classes = [str(names[key]) for key in sorted(names.keys(), key=lambda item: int(item) if str(item).isdigit() else str(item))]
    else:
        classes = [str(name) for name in names]
    _write_json(THREAT_CLASSES_PATH, {"classes": classes, "count": len(classes)})
    return classes


def load_threat_model(path: Path | str = THREAT_MODEL_PATH) -> tuple[Any, dict[str, Any]]:
    """Load the local threat model and expose only the classes it actually contains."""
    from ultralytics import YOLO

    metadata = ensure_threat_model(path)
    model = YOLO(str(Path(metadata["path"])))
    classes = inspect_threat_classes(model)
    metadata["classes"] = classes
    metadata["class_count"] = len(classes)
    return model, metadata
