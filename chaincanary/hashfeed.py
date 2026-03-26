"""
Remote hash feed manager — pull known-malicious SHA256 hashes
from a remote JSON feed, cache locally with TTL, merge with
the bundled db/known_malicious.json.

Feed format (same as local db):
{
    "sha256": ["hash1", "hash2", ...],
    "notes": {"hash1": "description", ...}
}

Cache format (adds metadata):
{
    "sha256": ["hash1", "hash2", ...],
    "fetched_at": 1711500000.0
}
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import requests

# Default feed URL — can be overridden via constructor
DEFAULT_FEED_URL = (
    "https://raw.githubusercontent.com/"
    "AetherCore-Dev/chaincanary/main/"
    "chaincanary/db/known_malicious.json"
)

# Default cache TTL: 24 hours
DEFAULT_TTL_SECONDS = 86400

# Default cache directory
DEFAULT_CACHE_DIR = Path.home() / ".chaincanary"


def merge_hash_sets(
    local: set[str],
    remote: set[str],
) -> set[str]:
    """
    Merge local and remote hash sets (union).

    Both sets are treated as authoritative — neither overrides.
    """
    return local | remote


class HashFeedManager:
    """
    Fetches, caches, and serves known-malicious hash sets.

    Lifecycle:
    1. Check local cache (valid if within TTL)
    2. If stale/missing, fetch from remote feed URL
    3. Cache result to disk
    4. Merge with bundled hashes
    """

    def __init__(
        self,
        feed_url: str = DEFAULT_FEED_URL,
        cache_dir: Path = DEFAULT_CACHE_DIR,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        timeout: int = 15,
    ) -> None:
        self.feed_url = feed_url
        self.cache_dir = cache_dir
        self.ttl_seconds = ttl_seconds
        self.timeout = timeout

    @property
    def cache_path(self) -> Path:
        return self.cache_dir / "hash_cache.json"

    def get_hashes(
        self,
        force_refresh: bool = False,
    ) -> set[str]:
        """
        Get the full set of known-malicious hashes.

        Checks cache first (unless force_refresh), then fetches
        from remote if stale/missing.
        """
        if not force_refresh:
            cached = self.load_cache()
            if cached is not None:
                return cached

        remote = self.fetch_remote()
        return remote

    def fetch_remote(self) -> set[str]:
        """
        Fetch hashes from the remote feed URL.

        Returns empty set on any failure (network, parse, etc.)
        — never raises.
        """
        try:
            resp = requests.get(
                self.feed_url,
                timeout=self.timeout,
                headers={
                    "User-Agent": "chaincanary/hashfeed",
                    "Accept": "application/json",
                },
            )
            if resp.status_code != 200:
                return set()

            data = resp.json()
            hashes = set(data.get("sha256", []))
            # Filter out placeholders
            hashes = {
                h for h in hashes
                if not h.startswith("PLACEHOLDER")
            }

            # Cache the result
            self._save_cache(hashes)
            return hashes

        except Exception:
            return set()

    def load_cache(self) -> set[str] | None:
        """
        Load hashes from local cache.

        Returns None if cache is missing, corrupted, or expired.
        """
        if not self.cache_path.exists():
            return None

        try:
            data = json.loads(self.cache_path.read_text())
        except (json.JSONDecodeError, OSError):
            return None

        fetched_at = data.get("fetched_at", 0)
        if time.time() - fetched_at > self.ttl_seconds:
            return None  # expired

        return set(data.get("sha256", []))

    def _save_cache(self, hashes: set[str]) -> None:
        """Save hashes to local cache with timestamp."""
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            cache_data = {
                "sha256": sorted(hashes),
                "fetched_at": time.time(),
            }
            self.cache_path.write_text(
                json.dumps(cache_data, indent=2),
            )
        except OSError:
            pass  # Cache write failure is non-fatal
