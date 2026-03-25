"""
Package downloader — fetch wheel from PyPI without installing.
Includes retry logic, timeout handling, and cache-safe download.
"""
from __future__ import annotations

import hashlib
import time
import tempfile
from pathlib import Path
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


PYPI_JSON_URL = "https://pypi.org/pypi/{package}/{version}/json"

# Retry config: 3 attempts, exponential backoff, on 5xx + connection errors
_RETRY_STRATEGY = Retry(
    total=3,
    backoff_factor=0.5,          # waits: 0.5s, 1.0s, 2.0s
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET"],
    raise_on_status=False,
)


def _make_session() -> requests.Session:
    """Create a requests session with retry + timeout defaults."""
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=_RETRY_STRATEGY)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    session.headers["User-Agent"] = "chaincanary/0.1 (security-scanner; https://github.com/allenenli/chaincanary)"
    return session


def _verify_hash(path: Path, expected_sha256: str) -> bool:
    """Verify downloaded file matches PyPI-provided SHA256."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest() == expected_sha256


def download_wheel(
    package: str,
    version: str,
    target_dir: Optional[Path] = None,
    verify_hash: bool = True,
) -> Optional[Path]:
    """
    Download a wheel (or sdist) from PyPI to target_dir.
    
    - Uses retry with exponential backoff
    - Verifies SHA256 hash from PyPI metadata
    - Returns the path to the downloaded file, or None on failure
    """
    session = _make_session()

    try:
        resp = session.get(
            PYPI_JSON_URL.format(package=package, version=version),
            timeout=15,
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return None

    urls = data.get("urls", [])
    wheel_urls = [u for u in urls if u["filename"].endswith(".whl")]
    sdist_urls = [u for u in urls if u["filename"].endswith(".tar.gz")]
    candidates = wheel_urls or sdist_urls
    if not candidates:
        return None

    artifact = candidates[0]
    filename = artifact["filename"]
    url = artifact["url"]
    expected_sha256 = artifact.get("digests", {}).get("sha256", "")

    if target_dir is None:
        target_dir = Path(tempfile.mkdtemp(prefix="chaincanary_"))
    target_dir.mkdir(parents=True, exist_ok=True)
    dest = target_dir / filename

    # Stream download
    try:
        file_resp = session.get(url, stream=True, timeout=60)
        file_resp.raise_for_status()
        with open(dest, "wb") as f:
            for chunk in file_resp.iter_content(chunk_size=65536):
                f.write(chunk)
    except Exception:
        if dest.exists():
            dest.unlink()
        return None

    # Verify integrity
    if verify_hash and expected_sha256:
        if not _verify_hash(dest, expected_sha256):
            dest.unlink()
            return None  # Hash mismatch — don't trust it

    return dest


def get_latest_safe_version(package: str, current_version: str) -> Optional[str]:
    """Find the latest version before current_version (safe rollback target)."""
    session = _make_session()
    try:
        resp = session.get(
            f"https://pypi.org/pypi/{package}/json",
            timeout=15,
        )
        if resp.status_code != 200:
            return None
        data = resp.json()

        from packaging.version import Version, InvalidVersion
        current = Version(current_version)
        candidates = []
        for v in data.get("releases", {}):
            try:
                parsed = Version(v)
                if parsed < current and not parsed.is_prerelease:
                    candidates.append(parsed)
            except InvalidVersion:
                pass
        return str(max(candidates)) if candidates else None
    except Exception:
        return None


def get_all_versions(package: str) -> list[str]:
    """Get all available versions from PyPI."""
    session = _make_session()
    try:
        resp = session.get(
            f"https://pypi.org/pypi/{package}/json",
            timeout=15,
        )
        if resp.status_code != 200:
            return []
        return list(resp.json().get("releases", {}).keys())
    except Exception:
        return []


def get_pypi_metadata(package: str, version: str) -> Optional[dict]:
    """Fetch full PyPI metadata for a package version."""
    session = _make_session()
    try:
        resp = session.get(
            PYPI_JSON_URL.format(package=package, version=version),
            timeout=15,
        )
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None
