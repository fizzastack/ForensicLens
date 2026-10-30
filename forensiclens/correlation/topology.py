"""ForensicLens Multi-Camera Topology and Spatial Configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CameraTransition:
    source_camera_id: str
    target_camera_id: str
    min_travel_seconds: float = 0.0
    max_travel_seconds: float = 60.0
    adjacency_weight: float = 1.0


@dataclass
class CameraTopology:
    """Configurable camera network topology for spatial-temporal event correlation."""

    cameras: dict[str, dict[str, Any]] = field(default_factory=dict)
    transitions: list[CameraTransition] = field(default_factory=list)

    def add_camera(self, camera_id: str, location_name: str = "", metadata: dict[str, Any] | None = None) -> None:
        self.cameras[camera_id] = {
            "camera_id": camera_id,
            "location_name": location_name,
            "metadata": metadata or {},
        }

    def add_transition(
        self,
        source_camera: str,
        target_camera: str,
        min_seconds: float = 0.0,
        max_seconds: float = 60.0,
        weight: float = 1.0,
    ) -> None:
        self.transitions.append(CameraTransition(
            source_camera_id=source_camera,
            target_camera_id=target_camera,
            min_travel_seconds=min_seconds,
            max_travel_seconds=max_seconds,
            adjacency_weight=weight,
        ))

    def is_plausible_transition(self, source_cam: str, target_cam: str, delta_t_seconds: float) -> tuple[bool, float]:
        """Check if transition between two cameras is physically plausible given time delta.

        Returns (is_plausible, score_modifier).
        """
        if source_cam == target_cam:
            return True, 1.0

        matching = [
            t for t in self.transitions
            if (t.source_camera_id == source_cam and t.target_camera_id == target_cam)
            or (t.source_camera_id == target_cam and t.target_camera_id == source_cam)
        ]

        if not matching:
            # If no explicit topology configured, fall back to conservative proximity scoring
            if 0.0 <= delta_t_seconds <= 120.0:
                score = max(0.2, 1.0 - (delta_t_seconds / 120.0))
                return True, score
            return False, 0.0

        for t in matching:
            if t.min_travel_seconds <= delta_t_seconds <= t.max_travel_seconds:
                # Optimal travel score in the middle of the window
                mid = (t.min_travel_seconds + t.max_travel_seconds) / 2.0
                spread = max(1.0, (t.max_travel_seconds - t.min_travel_seconds) / 2.0)
                norm_diff = abs(delta_t_seconds - mid) / spread
                score = max(0.3, (1.0 - 0.5 * norm_diff) * t.adjacency_weight)
                return True, min(1.0, score)

        return False, 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "camera_count": len(self.cameras),
            "cameras": list(self.cameras.values()),
            "transition_count": len(self.transitions),
            "transitions": [
                {
                    "source": t.source_camera_id,
                    "target": t.target_camera_id,
                    "min_travel_seconds": t.min_travel_seconds,
                    "max_travel_seconds": t.max_travel_seconds,
                    "weight": t.adjacency_weight,
                }
                for t in self.transitions
            ],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> CameraTopology:
        topology = cls()
        if not data:
            return topology
        for cam in data.get("cameras", []):
            topology.add_camera(cam.get("camera_id", ""), cam.get("location_name", ""), cam.get("metadata"))
        for t in data.get("transitions", []):
            topology.add_transition(
                t.get("source", ""),
                t.get("target", ""),
                float(t.get("min_travel_seconds", 0.0)),
                float(t.get("max_travel_seconds", 60.0)),
                float(t.get("weight", 1.0)),
            )
        return topology
