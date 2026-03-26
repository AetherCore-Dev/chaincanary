"""
Tests for remote hash feed — pull known_malicious_hashes from
a remote JSON feed, auto-update with caching.

Design:
- Remote feed URL is configurable (default: GitHub raw, HTTPS only)
- Local cache in ~/.chaincanary/hash_cache.json with 24h TTL
- Merges with bundled db/known_malicious.json
- `chaincanary update` forces refresh
- SHA256 hashes validated (exactly 64 hex chars)
"""

from __future__ import annotations

import json
import time
from unittest.mock import MagicMock, patch

import requests as req_lib

from chaincanary.hashfeed import (
    DEFAULT_FEED_URL,
    HashFeedManager,
    merge_hash_sets,
    validate_feed_url,
)

# Valid 64-char hex hashes for testing
_H1 = "a" * 64
_H2 = "b" * 64
_H3 = "c" * 64
_H4 = "d" * 64


# ── URL validation ───────────────────────────────────────────────


class TestFeedUrlValidation:
    """validate_feed_url blocks unsafe URLs."""

    def test_https_allowed(self):
        validate_feed_url("https://example.com/hashes.json")

    def test_http_blocked(self):
        import pytest
        with pytest.raises(ValueError, match="HTTPS"):
            validate_feed_url("http://example.com/hashes.json")

    def test_file_scheme_blocked(self):
        import pytest
        with pytest.raises(ValueError, match="HTTPS"):
            validate_feed_url("file:///etc/passwd")

    def test_loopback_blocked(self):
        import pytest
        with pytest.raises(ValueError, match="public host"):
            validate_feed_url("https://127.0.0.1/hashes.json")

    def test_private_ip_blocked(self):
        import pytest
        with pytest.raises(ValueError, match="public host"):
            validate_feed_url("https://192.168.1.1/hashes.json")

    def test_no_hostname_blocked(self):
        import pytest
        with pytest.raises(ValueError):
            validate_feed_url("https:///path")


# ── Merge logic ──────────────────────────────────────────────────


class TestMergeHashSets:
    """Merging local + remote hash sets."""

    def test_merge_disjoint_sets(self):
        result = merge_hash_sets({_H1, _H2}, {_H3, _H4})
        assert result == {_H1, _H2, _H3, _H4}

    def test_merge_overlapping_sets(self):
        result = merge_hash_sets({_H1, _H2}, {_H2, _H3})
        assert result == {_H1, _H2, _H3}

    def test_merge_empty_remote(self):
        result = merge_hash_sets({_H1}, set())
        assert result == {_H1}

    def test_merge_empty_local(self):
        result = merge_hash_sets(set(), {_H3})
        assert result == {_H3}

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
        """Successful remote fetch returns validated hash set."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"sha256": [_H1, _H2]}
        mock_get.return_value = mock_resp

        mgr = HashFeedManager(cache_dir=tmp_path)
        hashes = mgr.fetch_remote()
        assert hashes == {_H1, _H2}

    @patch("chaincanary.hashfeed.requests.get")
    def test_fetch_remote_filters_invalid_hashes(
        self, mock_get, tmp_path,
    ):
        """Invalid hashes (non-hex, wrong length) are filtered."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "sha256": [_H1, "short", "not-hex-!" * 8, "PLACEHOLDER_x"],
        }
        mock_get.return_value = mock_resp

        mgr = HashFeedManager(cache_dir=tmp_path)
        hashes = mgr.fetch_remote()
        assert hashes == {_H1}

    @patch("chaincanary.hashfeed.requests.get")
    def test_fetch_remote_failure_returns_empty(
        self, mock_get, tmp_path,
    ):
        """Network failure returns empty set, doesn't crash."""
        mock_get.side_effect = req_lib.ConnectionError("fail")

        mgr = HashFeedManager(cache_dir=tmp_path)
        hashes = mgr.fetch_remote()
        assert hashes == set()

    @patch("chaincanary.hashfeed.requests.get")
    def test_fetch_caches_result(self, mock_get, tmp_path):
        """Fetched hashes are cached to disk."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"sha256": [_H1]}
        mock_get.return_value = mock_resp

        mgr = HashFeedManager(cache_dir=tmp_path)
        mgr.fetch_remote()

        assert mgr.cache_path.exists()
        cached = json.loads(mgr.cache_path.read_text())
        assert _H1 in cached["sha256"]
        assert "fetched_at" in cached

    def test_load_cache_valid(self, tmp_path):
        """Valid cache file is loaded."""
        cache_data = {
            "sha256": [_H1, _H2],
            "fetched_at": time.time(),
        }
        cache_path = tmp_path / "hash_cache.json"
        cache_path.write_text(json.dumps(cache_data))

        mgr = HashFeedManager(cache_dir=tmp_path)
        hashes = mgr.load_cache()
        assert hashes == {_H1, _H2}

    def test_load_cache_expired(self, tmp_path):
        """Expired cache returns None."""
        cache_data = {
            "sha256": [_H1],
            "fetched_at": time.time() - 90000,
        }
        cache_path = tmp_path / "hash_cache.json"
        cache_path.write_text(json.dumps(cache_data))

        mgr = HashFeedManager(cache_dir=tmp_path, ttl_seconds=86400)
        assert mgr.load_cache() is None

    def test_load_cache_missing(self, tmp_path):
        """Missing cache returns None."""
        mgr = HashFeedManager(cache_dir=tmp_path)
        assert mgr.load_cache() is None

    def test_load_cache_corrupted(self, tmp_path):
        """Corrupted cache returns None."""
        cache_path = tmp_path / "hash_cache.json"
        cache_path.write_text("not json{{{")

        mgr = HashFeedManager(cache_dir=tmp_path)
        assert mgr.load_cache() is None

    @patch("chaincanary.hashfeed.requests.get")
    def test_get_hashes_uses_cache(self, mock_get, tmp_path):
        """get_hashes() prefers valid cache over network."""
        cache_data = {
            "sha256": [_H1],
            "fetched_at": time.time(),
        }
        cache_path = tmp_path / "hash_cache.json"
        cache_path.write_text(json.dumps(cache_data))

        mgr = HashFeedManager(cache_dir=tmp_path)
        hashes = mgr.get_hashes()

        mock_get.assert_not_called()
        assert _H1 in hashes

    @patch("chaincanary.hashfeed.requests.get")
    def test_get_hashes_fetches_when_cache_expired(
        self, mock_get, tmp_path,
    ):
        """get_hashes() fetches remote when cache is expired."""
        cache_data = {
            "sha256": [_H1],
            "fetched_at": time.time() - 90000,
        }
        cache_path = tmp_path / "hash_cache.json"
        cache_path.write_text(json.dumps(cache_data))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"sha256": [_H2]}
        mock_get.return_value = mock_resp

        mgr = HashFeedManager(cache_dir=tmp_path, ttl_seconds=86400)
        hashes = mgr.get_hashes()

        mock_get.assert_called_once()
        assert _H2 in hashes

    @patch("chaincanary.hashfeed.requests.get")
    def test_force_refresh_ignores_cache(self, mock_get, tmp_path):
        """force_refresh=True always fetches from remote."""
        cache_data = {
            "sha256": [_H1],
            "fetched_at": time.time(),
        }
        cache_path = tmp_path / "hash_cache.json"
        cache_path.write_text(json.dumps(cache_data))

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"sha256": [_H3]}
        mock_get.return_value = mock_resp

        mgr = HashFeedManager(cache_dir=tmp_path)
        hashes = mgr.get_hashes(force_refresh=True)

        mock_get.assert_called_once()
        assert _H3 in hashes


# ── CLI update command ───────────────────────────────────────────


class TestUpdateCommand:
    """'chaincanary update' forces hash feed refresh."""

    def test_update_command_exists(self):
        from click.testing import CliRunner

        from chaincanary.cli import main

        runner = CliRunner()
        result = runner.invoke(main, ["update", "--help"])
        assert result.exit_code == 0
        assert "update" in result.output.lower()
