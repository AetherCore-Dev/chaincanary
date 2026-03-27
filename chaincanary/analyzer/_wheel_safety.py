"""Wheel zip-safety validation."""

from __future__ import annotations

import zipfile

from chaincanary.models import Finding, Severity

# ── Safety limits (prevents zip-bomb / resource exhaustion attacks) ────────
MAX_FILES_IN_WHEEL = 50_000
MAX_SINGLE_FILE_BYTES = 50 * 1024 * 1024  # 50 MB
MAX_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024  # 500 MB


class WheelSecurityError(Exception):
    """Raised when a wheel file looks like a security trap."""


def safe_read_zip(zf: zipfile.ZipFile, name: str) -> bytes | None:
    """
    Read a file from a zip, enforcing size limits.
    Returns None if the file exceeds limits.
    """
    info = zf.getinfo(name)
    if info.file_size > MAX_SINGLE_FILE_BYTES:
        return None  # Skip oversized files
    return zf.read(name)


def validate_wheel_safety(zf: zipfile.ZipFile) -> Finding | None:
    """
    Check for zip-bomb and path traversal attacks.
    Returns a Finding if the wheel looks malicious, else None.
    """
    names = zf.namelist()

    # Too many files
    if len(names) > MAX_FILES_IN_WHEEL:
        return Finding(
            rule_id="WHEEL_ZIP_BOMB",
            severity=Severity.HIGH,
            title=f"Wheel contains {len(names):,} files — possible zip bomb",
            description="Legitimate packages rarely exceed a few hundred files.",
            evidence=f"File count: {len(names):,} (limit: {MAX_FILES_IN_WHEEL:,})",
            source="static",
        )

    # Path traversal
    for name in names:
        if ".." in name or name.startswith("/"):
            return Finding(
                rule_id="WHEEL_PATH_TRAVERSAL",
                severity=Severity.CRITICAL,
                title="Wheel contains path traversal entry",
                description="A file path in the wheel tries to escape the install directory.",
                evidence=f"Malicious path: {name}",
                source="static",
            )

    # Total uncompressed size
    total = sum(info.file_size for info in zf.infolist())
    if total > MAX_TOTAL_UNCOMPRESSED:
        return Finding(
            rule_id="WHEEL_OVERSIZED",
            severity=Severity.MEDIUM,
            title=f"Wheel unpacks to {total // (1024 * 1024):,} MB",
            description="Unusually large packages can indicate zip bombs.",
            evidence=f"Total uncompressed: {total // (1024 * 1024):,} MB",
            source="static",
        )

    return None
