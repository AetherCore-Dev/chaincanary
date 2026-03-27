"""Tests for the known-malicious hash database."""

from __future__ import annotations

import json
import re
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from chaincanary.analyzer._hash_check import (
    MALICIOUS_HASHES,
    _load_malicious_hashes,
    lookup_hash_metadata,
    sha256_file,
)


class TestHashDatabaseIntegrity:
    """Validate the known_malicious.json database."""

    def _load_db(self) -> dict:
        db_path = (
            Path(__file__).parent.parent
            / "chaincanary"
            / "db"
            / "known_malicious.json"
        )
        with open(db_path) as f:
            return json.load(f)

    def test_db_loads_without_error(self):
        """Database file loads and returns non-empty set."""
        hashes = _load_malicious_hashes()
        assert len(hashes) >= 10

    def test_no_placeholder_entries(self):
        """No PLACEHOLDER strings in the loaded hash set."""
        for h in MALICIOUS_HASHES:
            assert not h.startswith("PLACEHOLDER"), f"Placeholder found: {h}"

    def test_all_hashes_are_valid_sha256(self):
        """Every hash is exactly 64 lowercase hex characters."""
        sha256_re = re.compile(r"^[0-9a-f]{64}$")
        for h in MALICIOUS_HASHES:
            assert sha256_re.match(h), f"Invalid SHA-256: {h}"

    def test_entries_have_required_fields(self):
        """Every entry in the entries array has required metadata."""
        db = self._load_db()
        required = {"sha256", "package", "version", "attack_type", "source"}
        for entry in db.get("entries", []):
            missing = required - set(entry.keys())
            assert not missing, (
                f"Entry for {entry.get('package', '?')} missing: {missing}"
            )

    def test_sha256_list_matches_entries(self):
        """The flat sha256 list contains all entry hashes."""
        db = self._load_db()
        flat_set = set(db.get("sha256", []))
        for entry in db.get("entries", []):
            assert entry["sha256"] in flat_set, (
                f"Entry hash for {entry['package']} not in sha256 list"
            )

    def test_db_has_version_field(self):
        """Database has a version field for schema tracking."""
        db = self._load_db()
        assert "version" in db
        assert db["version"] >= 2

    def test_db_has_updated_date(self):
        """Database has an updated timestamp."""
        db = self._load_db()
        assert "updated" in db
        assert re.match(r"\d{4}-\d{2}-\d{2}", db["updated"])

    def test_litellm_fixture_hash_in_db(self):
        """The test fixture wheel hash is in the database."""
        fixture = Path(__file__).parent / "fixtures" / "litellm-1.82.8-py3-none-any.whl"
        if not fixture.exists():
            pytest.skip("Fixture wheel not available")
        h = sha256_file(fixture)
        assert h in MALICIOUS_HASHES, (
            f"Fixture hash {h} not found in malicious hash DB"
        )


class TestHashMetadataLookup:
    """Test metadata lookup for known malicious hashes."""

    def test_lookup_existing_hash(self):
        """Looking up a known hash returns metadata dict."""
        # Use the litellm fixture hash
        fixture = Path(__file__).parent / "fixtures" / "litellm-1.82.8-py3-none-any.whl"
        if not fixture.exists():
            pytest.skip("Fixture wheel not available")
        h = sha256_file(fixture)
        meta = lookup_hash_metadata(h)
        assert meta is not None
        assert meta["package"] == "litellm"
        assert meta["attack_type"] == "pth_persistence"

    def test_lookup_unknown_hash(self):
        """Looking up an unknown hash returns None."""
        result = lookup_hash_metadata("0" * 64)
        assert result is None

    def test_metadata_includes_source(self):
        """Metadata includes provenance source information."""
        fixture = Path(__file__).parent / "fixtures" / "litellm-1.82.8-py3-none-any.whl"
        if not fixture.exists():
            pytest.skip("Fixture wheel not available")
        h = sha256_file(fixture)
        meta = lookup_hash_metadata(h)
        assert meta is not None
        assert "source" in meta
        assert len(meta["source"]) > 10  # Not empty stub


class TestHashDetectionIntegration:
    """Test that hash detection produces enriched evidence."""

    def test_known_hash_finding_includes_metadata(self):
        """When a known malicious hash is detected, evidence includes metadata."""
        from chaincanary.analyzer.static import StaticAnalyzer

        fixture = Path(__file__).parent / "fixtures" / "litellm-1.82.8-py3-none-any.whl"
        if not fixture.exists():
            pytest.skip("Fixture wheel not available")

        analyzer = StaticAnalyzer()
        findings = analyzer.analyze_wheel(fixture, "litellm")

        hash_findings = [f for f in findings if f.rule_id == "KNOWN_MALICIOUS_HASH"]
        assert len(hash_findings) >= 1
        evidence = hash_findings[0].evidence
        assert "SHA256:" in evidence
        assert "Package: litellm" in evidence
        assert "Attack: pth_persistence" in evidence

    def test_clean_wheel_no_hash_finding(self):
        """A clean wheel does not trigger hash detection."""
        from chaincanary.analyzer.static import StaticAnalyzer

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a minimal clean wheel
            whl_path = Path(tmpdir) / "clean_pkg-1.0.0-py3-none-any.whl"
            with zipfile.ZipFile(whl_path, "w") as zf:
                zf.writestr(
                    "clean_pkg/__init__.py",
                    "# Clean package\n__version__ = '1.0.0'\n",
                )
                zf.writestr(
                    "clean_pkg-1.0.0.dist-info/METADATA",
                    "Metadata-Version: 2.1\nName: clean-pkg\nVersion: 1.0.0\n",
                )

            analyzer = StaticAnalyzer()
            findings = analyzer.analyze_wheel(whl_path, "clean_pkg")
            hash_findings = [f for f in findings if f.rule_id == "KNOWN_MALICIOUS_HASH"]
            assert len(hash_findings) == 0


class TestBackwardCompatibility:
    """Ensure the flat sha256 list still works for legacy consumers."""

    def test_flat_list_loads_correctly(self):
        """The flat sha256 list is loaded into MALICIOUS_HASHES."""
        assert isinstance(MALICIOUS_HASHES, set)
        assert len(MALICIOUS_HASHES) >= 10

    def test_hash_set_type(self):
        """MALICIOUS_HASHES is a set of strings."""
        for h in MALICIOUS_HASHES:
            assert isinstance(h, str)
