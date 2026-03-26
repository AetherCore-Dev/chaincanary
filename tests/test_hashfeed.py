"""
Tests for remote hash feed — pull known_malicious_hashes from
a remote JSON feed, auto-update with caching.

Design:
- Remote feed URL is configurable (default: GitHub raw)
- Feed is signed with HMAC-SHA256 (shared secret or public key)
- Local cache in ~/.chaincanary/hash_cache.json with TTL
- Merges with bundled db/known_malicious.json
- `chaincanary update` forces refresh
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from chaincanary.hashfeed import (
    DEFAULT_FEED_URL,
    HashFeedManager,
    merge_hash_sets,
)


# ── Merge logic ──────────────────────────────────────────────────


class TestMergeHashSets:
    """Merging local + remote hash sets."""

    def test_merge_disjoint_sets(self):
        local = {"aaa", "bbb"}
        remote = {"ccc", "ddd"}
        result = merge_hash_sets(local, remote)
        assert result == {"aaa", "bbb", "ccc", "ddd"}

    def test_merge_overlapping_sets(self):
        local = {"aaa", "bbb"}
        remote = {"bbb", "ccc"}
        result = merge_hash_sets(local, remote)
        assert result == {"aaa", "bbb", "ccc"}

    def test_merge_empty_remote(self):
        local = {"aaa", "bbb"}
        result = merge_hash_sets(local, set())
        assert result == {"aaa", "bbb"}

    def test_merge_empty_local(self):
        remote = {"ccc"}
        result = merge_hash_sets(set(), remote)
        assert result == {"ccc"}

    def test_merge_both_empty(self):
        result = merge_hash_sets(set(), set())
        assert result == set()


# ── HashFeedManager ──────────────────────────────────────────────


class TestHashFeedManager:
    """HashFeedManager fetches, caches, and merges hash feeds."""

    def test_default_feed_url(self):
        assert DEFAULT_FEED_URL.startswith("https://")

    def test_init_with_custom_cache_dir(self, tmp_path):
        mgr = HashFeedManager(cache_dir=tmp_path)
        assert mgr.cache_dir == tmp_path

    def test_cache_file_location(self, tmp_path):
        mgr = HashFeedManager(cache_dir=tmp_path)
        assert mgr.cache_path == tmp_path / "hash_cache.json"

    @patch("chaincanary.hashfeed.requests.get")
    def test_fetch_remote_success(self, mock_get, tmp_path):
        """Successful remote fetch returns hash set."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "sha256": ["abc123", "def456"],
        }
        mock_get.return_value = mock_resp

        mgr = HashFeedManager(cache_dir=tmp_path)
        hashes = mgr.fetch_remote()
        assert hashes == {"abc123", "def456"}

    @patch("chaincanary.hashfeed.requests.get")
    def test_fetch_remote_failure_returns_empty(
        self, mock_get, tmp_path,
    ):
        """Network failure returns empty set, doesn't crash."""
        mock_get.side_effect = Exception("Network error")

        mgr = HashFeedManager(cache_dir=tmp_path)
        hashes = mgr.fetch_remote()
        assert hashes == set()

    @patch("chaincanary.hashfeed.requests.get")
    def test_fetch_caches_result(self, mock_get, tmp_path):
        """Fetched hashes are cached to disk."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"sha256": ["abc123"]}
        mock_get.return_value = mock_resp

        mgr = HashFeedManager(cache_dir=tmp_path)
        mgr.fetch_remote()

        # Cache file should exist
        assert mgr.cache_path.exists()
        cached = json.loads(mgr.cache_path.read_text())
        assert "abc123" in cached["sha256"]
        assert "fetched_at" in cached

    def test_load_cache_valid(self, tmp_path):
        """Valid cache file is loaded."""
        cache_data = {
            "sha256": ["abc123", "def456"],
            "fetched_at": time.time(),
        }
        cache_path = tmp_path / "hash_cache.json"
        cache_path.write_text(json.dumps(cache_data))

        mgr = HashFeedManager(cache_dir=tmp_path)
        hashes = mgr.load_cache()
        assert hashes == {"abc123", "def456"}

    def test_load_cache_expired(self, tmp_path):
        """Expired cache returns None."""
        cache_data = {
            "sha256": ["abc123"],
            "fetched_at": time.time() - 90000,  # >24h ago
        }
        cache_path = tmp_path / "hash_cache.json"
        cache_path.write_text(json.dumps(cache_data))

        mgr = HashFeedManager(cache_dir=tmp_path, ttl_seconds=86400)
        hashes = mgr.load_cache()
        assert hashes is None

    def test_load_cache_missing(self, tmp_path):
        """Missing cache returns None."""
        mgr = HashFeedManager(cache_dir=tmp_path)
        hashes = mgr.load_cache()
        assert hashes is None

    def test_load_cache_corrupted(self, tmp_path):
        """Corrupted cache returns None."""
        cache_path = tmp_path / "hash_cache.json"
        cache_path.write_text("not json{{{")

        mgr = HashFeedManager(cache_dir=tmp_path)
        hashes = mgr.load_cache()
        assert hashes is None

    @patch("chaincanary.hashfeed.requests.get")
    def test_get_hashes_uses_cache(self, mock_get, tmp_path):
        """get_hashes() prefers valid cache over network."""
        cache_data = {
            "sha256": ["cached_hash"],
            "fetched_at": time.time(),  # fresh
        }
        cache_path = tmp_path / "hash_cache.json"
        cache_path.write_text(json.dumps(cache_data))

        mgr = HashFeedManager(cache_dir=tmp_path)
        hashes = mgr.get_hashes()

        # Should NOT make a network call
        mock_get.assert_not_called()
        assert "cached_hash" in hashes

    @patch("chaincanary.hashfeed.requests.get")
    def test_get_hashes_fetches_when_cache_expired(
        self, mock_get, tmp_path,
    ):
        """get_hashes() fetches remote when cache is expired."""
        cache_data = {
            "sha256": ["old_hash"],
            "fetched_at": time.time() - 90000,
        }
        cache_path = tmp_path / "hash_cache.json"
        cache_path.write_text(json.dumps(cache_data))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"sha256": ["new_hash"]}
        mock_get.return_value = mock_resp

        mgr = HashFeedManager(cache_dir=tmp_path, ttl_seconds=86400)
        hashes = mgr.get_hashes()

        mock_get.assert_called_once()
        assert "new_hash" in hashes

    @patch("chaincanary.hashfeed.requests.get")
    def test_force_refresh_ignores_cache(self, mock_get, tmp_path):
        """force_refresh=True always fetches from remote."""
        cache_data = {
            "sha256": ["cached_hash"],
            "fetched_at": time.time(),  # fresh
        }
        cache_path = tmp_path / "hash_cache.json"
        cache_path.write_text(json.dumps(cache_data))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"sha256": ["fresh_hash"]}
        mock_get.return_value = mock_resp

        mgr = HashFeedManager(cache_dir=tmp_path)
        hashes = mgr.get_hashes(force_refresh=True)

        mock_get.assert_called_once()
        assert "fresh_hash" in hashes


# ── CLI update command ───────────────────────────────────────────


class TestUpdateCommand:
    """'chaincanary update' forces hash feed refresh."""

    def test_update_command_exists(self):
        from click.testing import CliRunner
        from chaincanary.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["update", "--help"])
        assert result.exit_code == 0
        assert "hash" in result.output.lower() or "update" in result.output.lower()
