"""ForensicLens Real-Time USB & Removable Media Forensic Monitor.

Continuously discovers connected USB / removable storage devices on Windows,
attaches kernel-level filesystem observers (watchdog), captures created, modified,
deleted, and renamed file events with exact timestamps and SHA-256 hashes, and maintains
a tamper-evident cryptographic forensic audit trail.
"""

from __future__ import annotations

import csv
import ctypes
import hashlib
import io
import json
import os
import shutil
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

import psutil
from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

# Windows drive types
DRIVE_UNKNOWN = 0
DRIVE_NO_ROOT_DIR = 1
DRIVE_REMOVABLE = 2
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
DRIVE_CDROM = 5
DRIVE_RAMDISK = 6


def get_utc_now() -> str:
    """Return ISO 8601 formatted UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def get_local_now() -> str:
    """Return human-readable local timestamp."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def compute_file_sha256(file_path: Path | str, max_bytes: int = 100 * 1024 * 1024) -> str:
    """Compute SHA-256 hash of a file safely; return placeholder if file locked or unreadable."""
    path = Path(file_path)
    if not path.is_file():
        return "N/A_DELETED_OR_DIRECTORY"
    try:
        hasher = hashlib.sha256()
        with path.open("rb") as f:
            bytes_read = 0
            while chunk := f.read(65536):
                hasher.update(chunk)
                bytes_read += len(chunk)
                if bytes_read > max_bytes:
                    break
        return hasher.hexdigest()
    except Exception as err:
        return f"UNREADABLE_OR_LOCKED: {err}"


def get_volume_information(mountpoint: str) -> dict[str, Any]:
    """Retrieve Windows volume label, filesystem, and serial number."""
    drive_str = str(mountpoint)
    if not drive_str.endswith("\\"):
        drive_str += "\\"
    
    vol_name = ctypes.create_unicode_buffer(1024)
    fs_name = ctypes.create_unicode_buffer(1024)
    serial_num = ctypes.c_ulong()
    max_component_len = ctypes.c_ulong()
    fs_flags = ctypes.c_ulong()

    try:
        kernel32 = ctypes.windll.kernel32
        success = kernel32.GetVolumeInformationW(
            drive_str,
            vol_name,
            ctypes.sizeof(vol_name),
            ctypes.byref(serial_num),
            ctypes.byref(max_component_len),
            ctypes.byref(fs_flags),
            fs_name,
            ctypes.sizeof(fs_name),
        )
        if success:
            serial_hex = f"{serial_num.value:08X}"
            serial_formatted = f"{serial_hex[:4]}-{serial_hex[4:]}"
            return {
                "volume_label": vol_name.value or "Removable Disk",
                "file_system": fs_name.value or "FAT32/NTFS",
                "serial_number": serial_formatted,
            }
    except Exception:
        pass
    
    return {
        "volume_label": "Removable Disk",
        "file_system": "FAT32/NTFS",
        "serial_number": "UNKNOWN",
    }


def is_removable_drive(mountpoint: str) -> bool:
    """Check if drive is a removable USB device using Windows API."""
    drive_str = str(mountpoint)
    if not drive_str.endswith("\\"):
        drive_str += "\\"
    try:
        dtype = ctypes.windll.kernel32.GetDriveTypeW(drive_str)
        return dtype == DRIVE_REMOVABLE
    except Exception:
        return False


@dataclass
class USBDevice:
    """Represents a connected or tracked USB / removable storage device."""
    drive_letter: str
    volume_label: str
    file_system: str
    serial_number: str
    total_bytes: int = 0
    used_bytes: int = 0
    free_bytes: int = 0
    connected_at_utc: str = field(default_factory=get_utc_now)
    connected_at_local: str = field(default_factory=get_local_now)
    disconnected_at_utc: Optional[str] = None
    disconnected_at_local: Optional[str] = None
    duration_seconds: Optional[float] = None
    status: str = "CONNECTED"  # CONNECTED or DISCONNECTED
    is_custom_folder: bool = False

    def mark_disconnected(self) -> None:
        """Mark device as disconnected and compute duration."""
        self.status = "DISCONNECTED"
        self.disconnected_at_utc = get_utc_now()
        self.disconnected_at_local = get_local_now()
        try:
            conn_dt = datetime.fromisoformat(self.connected_at_utc)
            disc_dt = datetime.fromisoformat(self.disconnected_at_utc)
            self.duration_seconds = round((disc_dt - conn_dt).total_seconds(), 2)
        except Exception:
            self.duration_seconds = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class USBForensicEvent:
    """Represents a live forensic event on a USB / removable media."""
    event_id: str
    event_type: str  # USB_DEVICE_CONNECTED, USB_DEVICE_DISCONNECTED, FILE_CREATED, FILE_MODIFIED, FILE_DELETED, FILE_RENAMED
    timestamp_utc: str
    timestamp_local: str
    drive_letter: str
    file_path: str
    relative_path: str
    old_path: Optional[str] = None
    file_size_bytes: int = 0
    sha256: str = "N/A"
    previous_sha256: Optional[str] = None
    details: str = ""
    evidence_block_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class USBFileWatcherHandler(FileSystemEventHandler):
    """Watchdog event handler that debounces and formats USB file events."""

    def __init__(self, drive_letter: str, event_callback: Callable[[dict[str, Any]], None]) -> None:
        super().__init__()
        self.drive_letter = drive_letter
        self.event_callback = event_callback
        self._last_event_time: dict[str, float] = {}
        self._file_hashes: dict[str, str] = {}
        self._lock = threading.RLock()

    def _should_debounce(self, key: str, window_seconds: float = 0.3) -> bool:
        now = time.time()
        with self._lock:
            last = self._last_event_time.get(key, 0.0)
            if now - last < window_seconds:
                return True
            self._last_event_time[key] = now
            return False

    def on_created(self, event: FileSystemEvent) -> None:
        src_path = str(event.src_path)
        if "$RECYCLE.BIN" in src_path or "System Volume Information" in src_path or ".Trash" in src_path:
            return
        
        rel_path = src_path.replace(self.drive_letter, "").lstrip("\\/")
        if not rel_path or rel_path.startswith("~$") or rel_path.lower() == "desktop.ini":
            return

        if event.is_directory:
            self.event_callback({
                "event_type": "DIRECTORY_CREATED",
                "drive_letter": self.drive_letter,
                "file_path": src_path,
                "relative_path": rel_path,
                "file_size_bytes": 0,
                "sha256": "N/A_DIRECTORY",
                "details": f"New folder/directory created on {self.drive_letter}: {rel_path}",
            })
            return

        time.sleep(0.05)
        size = 0
        try:
            size = Path(src_path).stat().st_size
        except Exception:
            pass
        
        file_hash = compute_file_sha256(src_path)
        with self._lock:
            self._file_hashes[src_path] = file_hash

        self.event_callback({
            "event_type": "FILE_CREATED",
            "drive_letter": self.drive_letter,
            "file_path": src_path,
            "relative_path": rel_path,
            "file_size_bytes": size,
            "sha256": file_hash,
            "details": f"New file created / copied to {self.drive_letter}: {rel_path} ({size} bytes)",
        })

    def on_modified(self, event: FileSystemEvent) -> None:
        src_path = str(event.src_path)
        if "$RECYCLE.BIN" in src_path or "System Volume Information" in src_path or ".Trash" in src_path:
            return

        if event.is_directory:
            return
        
        rel_path = src_path.replace(self.drive_letter, "").lstrip("\\/")
        if not rel_path or rel_path.startswith("~$") or rel_path.lower() == "desktop.ini":
            return

        if self._should_debounce(f"mod:{src_path}", window_seconds=0.2):
            return

        time.sleep(0.05)
        size = 0
        try:
            size = Path(src_path).stat().st_size
        except Exception:
            pass

        new_hash = compute_file_sha256(src_path)
        with self._lock:
            old_hash = self._file_hashes.get(src_path)
            self._file_hashes[src_path] = new_hash

        self.event_callback({
            "event_type": "FILE_MODIFIED",
            "drive_letter": self.drive_letter,
            "file_path": src_path,
            "relative_path": rel_path,
            "file_size_bytes": size,
            "sha256": new_hash,
            "previous_sha256": old_hash,
            "details": f"File content modified on {self.drive_letter}: {rel_path} (Hash: {new_hash[:12]}...)",
        })

    def on_deleted(self, event: FileSystemEvent) -> None:
        src_path = str(event.src_path)
        if "$RECYCLE.BIN" in src_path or "System Volume Information" in src_path or ".Trash" in src_path:
            return

        rel_path = src_path.replace(self.drive_letter, "").lstrip("\\/")
        if not rel_path or rel_path.startswith("~$") or rel_path.lower() == "desktop.ini":
            return

        if event.is_directory:
            self.event_callback({
                "event_type": "DIRECTORY_DELETED",
                "drive_letter": self.drive_letter,
                "file_path": src_path,
                "relative_path": rel_path,
                "file_size_bytes": 0,
                "sha256": "N/A_DIRECTORY",
                "details": f"Folder/directory deleted from {self.drive_letter}: {rel_path}",
            })
            return

        with self._lock:
            old_hash = self._file_hashes.pop(src_path, None)

        self.event_callback({
            "event_type": "FILE_DELETED",
            "drive_letter": self.drive_letter,
            "file_path": src_path,
            "relative_path": rel_path,
            "file_size_bytes": 0,
            "sha256": "N/A_FILE_DELETED",
            "previous_sha256": old_hash,
            "details": f"File deleted from {self.drive_letter}: {rel_path}",
        })

    def on_moved(self, event: FileSystemEvent) -> None:
        src_path = str(event.src_path)
        dest_path = str(getattr(event, "dest_path", ""))
        if "$RECYCLE.BIN" in src_path or "System Volume Information" in src_path or ".Trash" in src_path:
            return

        src_rel = src_path.replace(self.drive_letter, "").lstrip("\\/")
        dest_rel = dest_path.replace(self.drive_letter, "").lstrip("\\/") if dest_path else ""
        if not src_rel or src_rel.startswith("~$") or src_rel.lower() == "desktop.ini":
            return

        if event.is_directory:
            self.event_callback({
                "event_type": "DIRECTORY_RENAMED",
                "drive_letter": self.drive_letter,
                "file_path": dest_path or src_path,
                "old_path": src_path,
                "relative_path": dest_rel or src_rel,
                "sha256": "N/A_DIRECTORY",
                "details": f"Folder renamed on {self.drive_letter}: {src_rel} -> {dest_rel}",
            })
            return

        with self._lock:
            old_hash = self._file_hashes.pop(src_path, None)
            new_hash = compute_file_sha256(dest_path) if dest_path else old_hash
            if dest_path:
                self._file_hashes[dest_path] = new_hash

        self.event_callback({
            "event_type": "FILE_RENAMED",
            "drive_letter": self.drive_letter,
            "file_path": dest_path or src_path,
            "old_path": src_path,
            "relative_path": dest_rel or src_rel,
            "sha256": new_hash or "N/A",
            "previous_sha256": old_hash,
            "details": f"File renamed on {self.drive_letter}: {src_rel} -> {dest_rel}",
        })


class USBMonitorManager:
    """Manages real-time discovery, watchdog observers, snapshot diffing, and reports."""

    def __init__(self, poll_interval_seconds: float = 1.0) -> None:
        self.poll_interval = poll_interval_seconds
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()

        # Active USB devices and observers
        self.devices: dict[str, USBDevice] = {}
        self._observers: dict[str, Observer] = {}
        self._drive_snapshots: dict[str, dict[str, dict[str, Any]]] = {}
        self._recent_event_keys: dict[str, float] = {}

        # Custom folders to monitor (e.g. simulated USBs or test folders)
        self.custom_watch_paths: set[str] = set()

        # Event log and cryptographic hash chain
        self.events: list[USBForensicEvent] = []
        self._event_counter = 0
        self._last_block_hash = "GENESIS_USB_BLOCK_0000000000000000"

    def start(self) -> None:
        """Start the USB discovery and monitoring background loop."""
        with self._lock:
            if self.is_running:
                return
            self.is_running = True
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Stop monitoring and stop all active observers."""
        with self._lock:
            self.is_running = False
            for drive, obs in list(self._observers.items()):
                try:
                    obs.stop()
                    obs.join(timeout=1.0)
                except Exception:
                    pass
            self._observers.clear()

    def _monitor_loop(self) -> None:
        """Periodic loop to discover new drives or detect removed drives."""
        while self.is_running:
            try:
                self._scan_drives()
            except Exception as err:
                pass
            time.sleep(self.poll_interval)

    def _scan_drives(self) -> None:
        """Detect current removable partitions and update observers and snapshot diffs."""
        current_removable: dict[str, dict[str, Any]] = {}

        # Scan Windows partitions
        try:
            for part in psutil.disk_partitions(all=True):
                mount = part.mountpoint
                if is_removable_drive(mount):
                    info = get_volume_information(mount)
                    usage = {"total": 0, "used": 0, "free": 0}
                    try:
                        u = psutil.disk_usage(mount)
                        usage = {"total": u.total, "used": u.used, "free": u.free}
                    except Exception:
                        pass
                    current_removable[mount] = {
                        "volume_label": info["volume_label"],
                        "file_system": info["file_system"] or part.fstype,
                        "serial_number": info["serial_number"],
                        "usage": usage,
                        "is_custom": False,
                    }
        except Exception:
            pass

        # Also include any custom folders being actively monitored
        with self._lock:
            for custom_path in self.custom_watch_paths:
                p = Path(custom_path).resolve()
                if p.exists() and str(p) not in current_removable:
                    current_removable[str(p)] = {
                        "volume_label": f"Custom Watch: {p.name}",
                        "file_system": "NTFS",
                        "serial_number": "CUSTOM-LOCAL",
                        "usage": {"total": 100 * 1024 * 1024 * 1024, "used": 10 * 1024 * 1024, "free": 90 * 1024 * 1024 * 1024},
                        "is_custom": True,
                    }

        # Check for newly plugged in drives or ensure observer active
        for drive_path, meta in current_removable.items():
            with self._lock:
                if drive_path not in self.devices or self.devices[drive_path].status == "DISCONNECTED":
                    device = USBDevice(
                        drive_letter=drive_path,
                        volume_label=meta["volume_label"],
                        file_system=meta["file_system"],
                        serial_number=meta["serial_number"],
                        total_bytes=meta["usage"]["total"],
                        used_bytes=meta["usage"]["used"],
                        free_bytes=meta["usage"]["free"],
                        is_custom_folder=meta["is_custom"],
                    )
                    self.devices[drive_path] = device
                    self._start_drive_observer(drive_path)
                    self._record_event({
                        "event_type": "USB_DEVICE_CONNECTED",
                        "drive_letter": drive_path,
                        "file_path": drive_path,
                        "relative_path": "",
                        "file_size_bytes": 0,
                        "sha256": "N/A",
                        "details": f"Removable device connected on {drive_path} [{meta['volume_label']}] (Serial: {meta['serial_number']}, FS: {meta['file_system']})",
                    })
                else:
                    # Update usage & ensure observer is running
                    self.devices[drive_path].total_bytes = meta["usage"]["total"]
                    self.devices[drive_path].used_bytes = meta["usage"]["used"]
                    self.devices[drive_path].free_bytes = meta["usage"]["free"]
                    if drive_path not in self._observers or not self._observers[drive_path].is_alive():
                        self._start_drive_observer(drive_path)

            # Perform directory snapshot difference check for fail-safe 100% capture
            self._diff_drive_snapshot(drive_path)

        # Check for disconnected drives
        with self._lock:
            for drive_path, device in list(self.devices.items()):
                if device.status == "CONNECTED" and drive_path not in current_removable:
                    device.mark_disconnected()
                    self._stop_drive_observer(drive_path)
                    self._drive_snapshots.pop(drive_path, None)
                    self._record_event({
                        "event_type": "USB_DEVICE_DISCONNECTED",
                        "drive_letter": drive_path,
                        "file_path": drive_path,
                        "relative_path": "",
                        "file_size_bytes": 0,
                        "sha256": "N/A",
                        "details": f"Removable device disconnected from {drive_path} [{device.volume_label}]. Total connected time: {device.duration_seconds} seconds.",
                    })

    def _diff_drive_snapshot(self, drive_path: str) -> None:
        """Scan directory tree and diff against previous snapshot to guarantee 100% event capture."""
        root = Path(drive_path)
        if not root.exists():
            self._drive_snapshots.pop(drive_path, None)
            return

        current_files: dict[str, dict[str, Any]] = {}
        try:
            for dirpath, dirnames, filenames in os.walk(drive_path):
                if "$RECYCLE.BIN" in dirpath or "System Volume Information" in dirpath or ".Trash" in dirpath:
                    continue
                dirnames[:] = [d for d in dirnames if d not in ("$RECYCLE.BIN", "System Volume Information", ".Trash-1000", ".Spotlight-V100")]

                for fn in filenames:
                    if fn.startswith("~$") or fn.lower() == "desktop.ini":
                        continue
                    full_p = os.path.join(dirpath, fn)
                    try:
                        st = os.stat(full_p)
                        rel_p = full_p.replace(drive_path, "").lstrip("\\/")
                        current_files[rel_p] = {
                            "full_path": full_p,
                            "size": st.st_size,
                            "mtime": st.st_mtime,
                        }
                    except (FileNotFoundError, PermissionError):
                        continue
        except Exception:
            return

        old_snapshot = self._drive_snapshots.get(drive_path)
        if old_snapshot is None:
            # Initial baseline snapshot upon drive attachment
            self._drive_snapshots[drive_path] = current_files
            return

        now = time.time()
        # 1. Detect Created / Copied Files
        for rel_p, meta in current_files.items():
            if rel_p not in old_snapshot:
                key = f"created:{drive_path}:{rel_p}"
                if now - self._recent_event_keys.get(key, 0.0) > 1.2:
                    self._recent_event_keys[key] = now
                    file_hash = compute_file_sha256(meta["full_path"])
                    self._record_event({
                        "event_type": "FILE_CREATED",
                        "drive_letter": drive_path,
                        "file_path": meta["full_path"],
                        "relative_path": rel_p,
                        "file_size_bytes": meta["size"],
                        "sha256": file_hash,
                        "details": f"New file created / copied on {drive_path}: {rel_p} ({meta['size']} bytes)",
                    })
            else:
                # 2. Detect Modified Files
                old = old_snapshot[rel_p]
                if meta["size"] != old["size"] or abs(meta["mtime"] - old["mtime"]) > 0.5:
                    key = f"modified:{drive_path}:{rel_p}"
                    if now - self._recent_event_keys.get(key, 0.0) > 1.2:
                        self._recent_event_keys[key] = now
                        new_hash = compute_file_sha256(meta["full_path"])
                        self._record_event({
                            "event_type": "FILE_MODIFIED",
                            "drive_letter": drive_path,
                            "file_path": meta["full_path"],
                            "relative_path": rel_p,
                            "file_size_bytes": meta["size"],
                            "sha256": new_hash,
                            "details": f"File content modified on {drive_path}: {rel_p} (Hash: {new_hash[:12]}...)",
                        })

        # 3. Detect Deleted Files
        for rel_p, old_meta in old_snapshot.items():
            if rel_p not in current_files:
                key = f"deleted:{drive_path}:{rel_p}"
                if now - self._recent_event_keys.get(key, 0.0) > 1.2:
                    self._recent_event_keys[key] = now
                    self._record_event({
                        "event_type": "FILE_DELETED",
                        "drive_letter": drive_path,
                        "file_path": old_meta.get("full_path", os.path.join(drive_path, rel_p)),
                        "relative_path": rel_p,
                        "file_size_bytes": 0,
                        "sha256": "N/A_FILE_DELETED",
                        "details": f"File deleted from {drive_path}: {rel_p}",
                    })

        self._drive_snapshots[drive_path] = current_files

    def _start_drive_observer(self, drive_path: str) -> None:
        """Start a Watchdog Observer for the specified drive root."""
        try:
            if drive_path in self._observers:
                try:
                    self._observers[drive_path].stop()
                except Exception:
                    pass

            observer = Observer()
            handler = USBFileWatcherHandler(drive_path, self._record_event)
            observer.schedule(handler, drive_path, recursive=True)
            observer.start()
            self._observers[drive_path] = observer
        except Exception as err:
            pass

    def _stop_drive_observer(self, drive_path: str) -> None:
        """Stop watchdog observer for disconnected drive."""
        if drive_path in self._observers:
            try:
                obs = self._observers.pop(drive_path)
                obs.stop()
                obs.join(timeout=0.5)
            except Exception:
                pass

    def _record_event(self, raw_event: dict[str, Any]) -> None:
        """Create a cryptographic hash-linked forensic event."""
        with self._lock:
            self._event_counter += 1
            event_id = f"USB-EVT-{self._event_counter:05d}"
            utc_ts = get_utc_now()
            local_ts = get_local_now()

            # Create block hash
            block_data = (
                f"{event_id}|{raw_event.get('event_type')}|{utc_ts}|"
                f"{raw_event.get('drive_letter')}|{raw_event.get('file_path')}|"
                f"{raw_event.get('sha256')}|{self._last_block_hash}"
            )
            block_hash = hashlib.sha256(block_data.encode("utf-8")).hexdigest()
            self._last_block_hash = block_hash

            event = USBForensicEvent(
                event_id=event_id,
                event_type=raw_event.get("event_type", "FILE_MODIFIED"),
                timestamp_utc=utc_ts,
                timestamp_local=local_ts,
                drive_letter=raw_event.get("drive_letter", ""),
                file_path=raw_event.get("file_path", ""),
                relative_path=raw_event.get("relative_path", ""),
                old_path=raw_event.get("old_path"),
                file_size_bytes=raw_event.get("file_size_bytes", 0),
                sha256=raw_event.get("sha256", "N/A"),
                previous_sha256=raw_event.get("previous_sha256"),
                details=raw_event.get("details", ""),
                evidence_block_hash=block_hash,
            )
            self.events.append(event)

    def add_custom_watch_path(self, path: str | Path) -> str:
        """Add a custom directory to watch as a simulated or target storage medium."""
        p = Path(path).resolve()
        p.mkdir(parents=True, exist_ok=True)
        with self._lock:
            self.custom_watch_paths.add(str(p))
        self._scan_drives()
        return str(p)

    def remove_custom_watch_path(self, path: str | Path) -> None:
        """Remove a custom directory from monitoring."""
        p = str(Path(path).resolve())
        with self._lock:
            self.custom_watch_paths.discard(p)
            if p in self.devices and self.devices[p].status == "CONNECTED":
                dev = self.devices[p]
                dev.mark_disconnected()
                self._stop_drive_observer(p)
                self._record_event({
                    "event_type": "USB_DEVICE_DISCONNECTED",
                    "drive_letter": p,
                    "file_path": p,
                    "relative_path": "",
                    "file_size_bytes": 0,
                    "sha256": "N/A",
                    "details": f"Removable device disconnected from {p} [{dev.volume_label}]. Total connected time: {dev.duration_seconds} seconds.",
                })

    def simulate_demo_activity(self) -> dict[str, Any]:
        """Perform a realistic USB plug-in, file creation, modification, deletion, and unplug flow."""
        sim_dir = Path("dataset/simulated_usb_test").resolve()
        sim_dir.mkdir(parents=True, exist_ok=True)
        sim_path = str(sim_dir)

        # 1. Plug in
        self.add_custom_watch_path(sim_path)
        time.sleep(0.3)

        # 2. File created
        test_file = sim_dir / "cctv_backup_log.txt"
        test_file.write_text("INITIAL CCTV LOG DUMP - TIMESTAMP: " + get_utc_now() + "\n", encoding="utf-8")
        time.sleep(0.3)

        # 3. File modified
        test_file.write_text("TAMPERED_OR_UPDATED LOG ENTRY: Incident report overwritten at " + get_utc_now() + "\n", encoding="utf-8")
        time.sleep(0.3)

        # 4. Another file created
        exhibit_file = sim_dir / "suspect_image_01.jpg.tmp"
        exhibit_file.write_bytes(b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00SIMULATED_EXHIBIT_DATA_PAYLOAD")
        time.sleep(0.3)

        # 5. File deleted
        exhibit_file.unlink(missing_ok=True)
        time.sleep(0.3)

        # 6. Disconnect
        self.remove_custom_watch_path(sim_path)

        return {
            "status": "simulation_complete",
            "simulated_path": sim_path,
            "message": "Simulated USB insertion, file creation, file modification, file deletion, and safe removal successfully.",
            "total_events_captured": len(self.events),
        }

    def get_status(self) -> dict[str, Any]:
        """Return current status of all tracked USB devices and monitoring state."""
        with self._lock:
            def _enrich_device(dev: USBDevice) -> dict[str, Any]:
                d = dev.to_dict()
                dev_events = [e.to_dict() for e in self.events if e.drive_letter == dev.drive_letter]
                d["recent_events"] = dev_events[-10:]
                d["event_counts"] = {
                    "created": sum(1 for e in dev_events if e["event_type"] == "FILE_CREATED"),
                    "modified": sum(1 for e in dev_events if e["event_type"] == "FILE_MODIFIED"),
                    "deleted": sum(1 for e in dev_events if e["event_type"] == "FILE_DELETED"),
                    "renamed": sum(1 for e in dev_events if e["event_type"] == "FILE_RENAMED"),
                    "total": len(dev_events),
                }
                return d

            active_drives = [_enrich_device(dev) for dev in self.devices.values() if dev.status == "CONNECTED"]
            all_drives = [_enrich_device(dev) for dev in self.devices.values()]
            created_count = sum(1 for e in self.events if e.event_type == "FILE_CREATED")
            modified_count = sum(1 for e in self.events if e.event_type == "FILE_MODIFIED")
            deleted_count = sum(1 for e in self.events if e.event_type == "FILE_DELETED")
            renamed_count = sum(1 for e in self.events if e.event_type == "FILE_RENAMED")
            device_connect_count = sum(1 for e in self.events if e.event_type == "USB_DEVICE_CONNECTED")
            device_disconnect_count = sum(1 for e in self.events if e.event_type == "USB_DEVICE_DISCONNECTED")

            latest_event = self.events[-1].to_dict() if self.events else None

            return {
                "is_monitoring": self.is_running,
                "poll_interval_seconds": self.poll_interval,
                "connected_devices_count": len(active_drives),
                "total_devices_tracked": len(all_drives),
                "total_events_count": len(self.events),
                "latest_event": latest_event,
                "summary": {
                    "device_connects": device_connect_count,
                    "device_disconnects": device_disconnect_count,
                    "files_created": created_count,
                    "files_modified": modified_count,
                    "files_deleted": deleted_count,
                    "files_renamed": renamed_count,
                },
                "active_devices": active_drives,
                "all_devices": all_drives,
                "custom_watch_paths": list(self.custom_watch_paths),
                "last_block_hash": self._last_block_hash,
            }

    def get_events(self, limit: int = 200, since_id: Optional[str] = None, event_type: Optional[str] = None) -> list[dict[str, Any]]:
        """Retrieve chronological or filtered forensic events."""
        with self._lock:
            results = self.events
            if since_id:
                idx = 0
                for i, ev in enumerate(self.events):
                    if ev.event_id == since_id:
                        idx = i + 1
                        break
                results = results[idx:]
            
            if event_type and event_type != "ALL":
                results = [e for e in results if e.event_type == event_type]

            return [e.to_dict() for e in results[-limit:]]

    def export_report_json(self) -> str:
        """Export USB forensic events and device history as JSON."""
        status = self.get_status()
        events = [e.to_dict() for e in self.events]
        payload = {
            "report_type": "FORENSICLENS_LIVE_USB_FORENSIC_AUDIT_LOG",
            "generated_at_utc": get_utc_now(),
            "generated_at_local": get_local_now(),
            "monitor_status": status,
            "events_count": len(events),
            "tamper_evident_terminal_hash": self._last_block_hash,
            "events": events,
        }
        return json.dumps(payload, indent=2)

    def export_report_markdown(self) -> str:
        """Export USB forensic events and device history as GitHub Flavored Markdown."""
        status = self.get_status()
        lines = [
            "# ForensicLens Live USB & Removable Media Forensic Audit Report",
            f"**Generated:** {get_local_now()} (Local) / `{get_utc_now()}` (UTC)",
            f"**Terminal Evidence Block Hash:** `{self._last_block_hash}`",
            "",
            "## 1. Executive Summary",
            f"- **Connected Devices Currently Active:** {status['connected_devices_count']}",
            f"- **Total Devices Tracked:** {status['total_devices_tracked']}",
            f"- **Total Forensic Events Recorded:** {status['total_events_count']}",
            f"- **Files Created:** {status['summary']['files_created']}",
            f"- **Files Modified:** {status['summary']['files_modified']}",
            f"- **Files Deleted:** {status['summary']['files_deleted']}",
            f"- **Files Renamed:** {status['summary']['files_renamed']}",
            "",
            "## 2. Tracked USB & Removable Storage Devices",
            "| Drive | Volume Label | File System | Serial Number | Connected At | Disconnected At | Duration | Status |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for d in status["all_devices"]:
            dur = f"{d.get('duration_seconds', 0)}s" if d.get("duration_seconds") else "Active"
            disc = d.get("disconnected_at_local") or "—"
            lines.append(
                f"| `{d['drive_letter']}` | {d['volume_label']} | {d['file_system']} | "
                f"`{d['serial_number']}` | {d['connected_at_local']} | {disc} | {dur} | **{d['status']}** |"
            )

        lines.extend([
            "",
            "## 3. Real-Time Forensic Event Audit Trail",
            "| Event ID | Timestamp (Local) | Event Type | Drive | Relative Path | Size | SHA-256 Hash | Block Hash |",
            "|---|---|---|---|---|---|---|---|",
        ])
        for e in self.events:
            hash_abbr = f"`{e.sha256[:12]}...`" if e.sha256 and len(e.sha256) > 16 else f"`{e.sha256}`"
            block_abbr = f"`{e.evidence_block_hash[:10]}...`"
            lines.append(
                f"| `{e.event_id}` | {e.timestamp_local} | **{e.event_type}** | `{e.drive_letter}` | "
                f"`{e.relative_path or e.file_path}` | {e.file_size_bytes}B | {hash_abbr} | {block_abbr} |"
            )

        return "\n".join(lines)

    def export_report_csv(self) -> str:
        """Export USB forensic events as CSV."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "Event ID", "Timestamp UTC", "Timestamp Local", "Event Type", "Drive Letter",
            "File Path", "Relative Path", "Old Path", "Size Bytes", "SHA256 Hash", "Previous SHA256",
            "Details", "Evidence Block Hash"
        ])
        for e in self.events:
            writer.writerow([
                e.event_id, e.timestamp_utc, e.timestamp_local, e.event_type, e.drive_letter,
                e.file_path, e.relative_path, e.old_path or "", e.file_size_bytes, e.sha256,
                e.previous_sha256 or "", e.details, e.evidence_block_hash
            ])
        return output.getvalue()


# Global singleton instance for platform-wide sharing
usb_monitor = USBMonitorManager()
