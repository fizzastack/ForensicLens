"""ForensicLens Safe Test-Only Data Erasure and Sanitization Module.

Provides cryptographically verifiable file-level sanitization workflows for
temporary / test evidence copies while strictly protecting original source evidence.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .preservation import hash_file, utc_now


PROTECTED_DIR_NAMES = {"raw", "dataset", "dataset/raw", "dataset/raw/video", "dataset/video"}


class ProtectedEvidenceError(PermissionError):
    """Raised when attempting to sanitize or overwrite protected source evidence."""
    pass


class ErasureCertificate:
    """Standardized certificate documenting secure erasure of a temporary/test file."""

    def __init__(
        self,
        certificate_id: str,
        target_path: str,
        original_size_bytes: int,
        original_sha256: str,
        original_md5: str,
        sanitization_method: str,
        passes_completed: int,
        verification_status: str,
        timestamp_utc: str,
        operator_id: str = "ForensicLens_Automated_Sanitizer",
        limitations: str | None = None,
    ) -> None:
        self.certificate_id = certificate_id
        self.target_path = target_path
        self.original_size_bytes = original_size_bytes
        self.original_sha256 = original_sha256
        self.original_md5 = original_md5
        self.sanitization_method = sanitization_method
        self.passes_completed = passes_completed
        self.verification_status = verification_status
        self.timestamp_utc = timestamp_utc
        self.operator_id = operator_id
        self.limitations = limitations or (
            "NOTICE OF LIMITATION: This operation performed logical file-level overwrite sanitization "
            "on an explicitly designated temporary/test copy. It does not constitute physical magnetic "
            "degaussing, ATA Secure Erase, or flash translation layer (FTL) wear-leveling bypass. "
            "Protected source evidence repositories are strictly excluded from this operation."
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "certificate_id": self.certificate_id,
            "target_path": self.target_path,
            "original_size_bytes": self.original_size_bytes,
            "original_sha256": self.original_sha256,
            "original_md5": self.original_md5,
            "sanitization_method": self.sanitization_method,
            "passes_completed": self.passes_completed,
            "verification_status": self.verification_status,
            "timestamp_utc": self.timestamp_utc,
            "operator_id": self.operator_id,
            "forensic_limitations_notice": self.limitations,
        }


def is_path_protected(path: Path, protected_roots: list[Path] | None = None) -> bool:
    """Check if the given path resides within protected source directories."""
    resolved = path.resolve()
    
    # Check default workspace protected roots
    workspace_root = Path.cwd().resolve()
    default_protected = [
        workspace_root / "dataset",
        workspace_root / "dataset" / "raw",
        workspace_root / "dataset" / "raw" / "video",
        workspace_root / "dataset" / "video",
    ]

    all_protected = list(default_protected)
    if protected_roots:
        all_protected.extend([p.resolve() for p in protected_roots])

    for root in all_protected:
        if root.exists():
            try:
                resolved.relative_to(root)
                return True
            except ValueError:
                pass

    # Check for name patterns in path parts
    parts = [part.lower() for part in resolved.parts]
    if "dataset" in parts and "raw" in parts:
        return True

    return False


def sanitize_test_file(
    file_path: Path | str,
    method: str = "NIST_SP_800_88_CLEAR",
    protected_roots: list[Path] | None = None,
    operator_id: str = "ForensicInvestigator",
    unlink_after_sanitization: bool = True,
) -> ErasureCertificate:
    """Safely sanitize a temporary/test file and generate an ErasureCertificate.

    Methods:
    - 'NIST_SP_800_88_CLEAR': 1-pass pseudorandom/zero overwrite + flush.
    - 'DOD_5220_22_M_3_PASS': 3-pass overwrite (0x00, 0xFF, random bytes) + flush.
    """
    path = Path(file_path).resolve()

    if not path.is_file():
        raise FileNotFoundError(f"Target file does not exist or is not a regular file: {path}")

    # 1. Enforce strict protection rules
    if is_path_protected(path, protected_roots):
        raise ProtectedEvidenceError(
            f"REFUSAL: Target path '{path}' is located inside a protected source evidence directory! "
            "ForensicLens strictly forbids sanitization of source evidence."
        )

    # 2. Record pre-sanitization integrity snapshot
    hashes = hash_file(path)
    file_size = path.stat().st_size
    original_sha256 = hashes["sha256"]
    original_md5 = hashes["md5"]

    # 3. Perform documented overwrite passes
    passes = 0
    if method == "DOD_5220_22_M_3_PASS":
        # Pass 1: Zeroes (0x00)
        with path.open("r+b") as f:
            f.seek(0)
            f.write(b"\x00" * file_size)
            f.flush()
            os.fsync(f.fileno())
        passes += 1

        # Pass 2: Ones (0xFF)
        with path.open("r+b") as f:
            f.seek(0)
            f.write(b"\xFF" * file_size)
            f.flush()
            os.fsync(f.fileno())
        passes += 1

        # Pass 3: Cryptographic random bytes
        with path.open("r+b") as f:
            f.seek(0)
            f.write(os.urandom(file_size))
            f.flush()
            os.fsync(f.fileno())
        passes += 1
    else:
        # Default: NIST SP 800-88 Clear (Pseudorandom bytes)
        with path.open("r+b") as f:
            f.seek(0)
            f.write(os.urandom(file_size))
            f.flush()
            os.fsync(f.fileno())
        passes += 1

    # 4. Verify post-overwrite hash differs from original
    post_hashes = hash_file(path)
    if file_size > 0 and post_hashes["sha256"] == original_sha256:
        verification_status = "OVERWRITE_FAILED_HASH_MATCH"
    else:
        verification_status = "OVERWRITE_VERIFIED"

    # 5. Optionally unlink/remove test file
    if unlink_after_sanitization and verification_status == "OVERWRITE_VERIFIED":
        path.unlink()
        verification_status = "OVERWRITE_VERIFIED_AND_UNLINKED"

    cert_id = f"CERT-ERASURE-{datetime.now(tz=timezone.utc).strftime('%Y%m%d%H%M%S')}-{original_sha256[:8]}"

    certificate = ErasureCertificate(
        certificate_id=cert_id,
        target_path=str(path),
        original_size_bytes=file_size,
        original_sha256=original_sha256,
        original_md5=original_md5,
        sanitization_method=method,
        passes_completed=passes,
        verification_status=verification_status,
        timestamp_utc=utc_now(),
        operator_id=operator_id,
    )

    return certificate
