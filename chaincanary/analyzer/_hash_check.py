"""Known-malicious hash database and file hashing."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


def _load_db() -> dict:
    """Load the full malicious hash database."""
    db_path = Path(__file__).parent.parent / "db" / "known_malicious.json"
    if not db_path.exists():
        return {}
    with open(db_path, encoding="utf-8") as f:
        return json.load(f)


def _load_malicious_hashes() -> set[str]:
    """Extract the flat set of SHA-256 hashes for fast lookup."""
    data = _load_db()
    hashes: set[str] = set()
    for h in data.get("sha256", []):
        if not h.startswith("PLACEHOLDER"):
            hashes.add(h)
    for entry in data.get("entries", []):
        sha = entry.get("sha256", "")
        if sha and not sha.startswith("PLACEHOLDER"):
            hashes.add(sha)
    return hashes


MALICIOUS_HASHES: set[str] = _load_malicious_hashes()


def lookup_hash_metadata(file_hash: str) -> dict | None:
    """Look up metadata for a known malicious hash.

    Returns a dict with package, version, attack_type, source, etc.
    or None if the hash is not in the database.
    """
    data = _load_db()
    for entry in data.get("entries", []):
        if entry.get("sha256") == file_hash:
            return entry
    return None


def sha256_file(path: Path) -> str:
    """Return the hex SHA-256 digest of *path*."""
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()
