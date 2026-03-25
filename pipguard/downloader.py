"""
Package downloader — fetch wheel from PyPI without installing.
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Optional
import requests


PYPI_JSON_URL = "https://pypi.org/pypi/{package}/{version}/json"
PYPI_SIMPLE_URL = "https://pypi.org/simple/{package}/"


def get_latest_safe_version(package: str, current_version: str) -> Optional[str]:
    """
    Find the latest version before current_version.
    Used to suggest a safe fallback.
    """
    try:
        resp = requests.get(
            f"https://pypi.org/pypi/{package}/json",
            timeout=10
        )
        if resp.status_code != 200:
            return None
        data = resp.json()
        versions = list(data.get("releases", {}).keys())

        from packaging.version import Version, InvalidVersion
        parsed = []
        for v in versions:
            try:
                parsed.append(Version(v))
            except InvalidVersion:
                pass

        current = Version(current_version)
        candidates = sorted([v for v in parsed if v < current], reverse=True)
        return str(candidates[0]) if candidates else None
    except Exception:
        return None


def get_all_versions(package: str) -> list[str]:
    """Get all available versions of a package from PyPI."""
    try:
        resp = requests.get(
            f"https://pypi.org/pypi/{package}/json",
            timeout=10
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        return list(data.get("releases", {}).keys())
    except Exception:
        return []


def download_wheel(
    package: str,
    version: str,
    target_dir: Optional[Path] = None,
) -> Optional[Path]:
    """
    Download wheel (or sdist) from PyPI to a temp directory.
    Returns path to downloaded file, or None on failure.
    """
    try:
        resp = requests.get(
            PYPI_JSON_URL.format(package=package, version=version),
            timeout=10
        )
        if resp.status_code == 404:
            return None
        resp.raise_for_status()

        data = resp.json()
        urls = data.get("urls", [])

        # Prefer wheel over sdist
        wheel_urls = [u for u in urls if u["filename"].endswith(".whl")]
        sdist_urls = [u for u in urls if u["filename"].endswith(".tar.gz")]

        download_candidates = wheel_urls or sdist_urls
        if not download_candidates:
            return None

        artifact = download_candidates[0]
        filename = artifact["filename"]
        url = artifact["url"]

        if target_dir is None:
            target_dir = Path(tempfile.mkdtemp(prefix="pipguard_"))

        target_dir.mkdir(parents=True, exist_ok=True)
        dest = target_dir / filename

        # Stream download
        file_resp = requests.get(url, stream=True, timeout=30)
        file_resp.raise_for_status()

        with open(dest, "wb") as f:
            for chunk in file_resp.iter_content(chunk_size=8192):
                f.write(chunk)

        return dest

    except Exception as e:
        return None
