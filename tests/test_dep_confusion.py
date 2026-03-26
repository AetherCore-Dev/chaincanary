"""
Tests for dependency confusion detection.

Dependency confusion attacks occur when an attacker publishes a
malicious package on PyPI with the same name as an internal/private
package. pip may prefer the public version if the version number
is higher.

Detection strategy:
1. User declares internal package name patterns via --internal-names
2. If a package matches an internal pattern AND exists on public PyPI,
   flag as potential dependency confusion
3. Also detect common internal naming patterns heuristically
"""

from __future__ import annotations

from unittest.mock import patch

from chaincanary.models import Severity
from chaincanary.safety_checks import (
    check_dependency_confusion,
    is_internal_name_pattern,
)

# ── Heuristic internal name detection ────────────────────────────


class TestInternalNamePattern:
    """Detect package names that look like internal/private packages."""

    def test_prefixed_internal(self):
        """Common internal prefix patterns."""
        assert is_internal_name_pattern("mycompany-auth")
        assert is_internal_name_pattern("acme-internal-utils")
        assert is_internal_name_pattern("corp-data-pipeline")

    def test_suffixed_internal(self):
        """Common internal suffix patterns."""
        assert is_internal_name_pattern("auth-internal")
        assert is_internal_name_pattern("utils-private")

    def test_public_packages_no_flag(self):
        """Well-known public packages should NOT match."""
        assert not is_internal_name_pattern("requests")
        assert not is_internal_name_pattern("flask")
        assert not is_internal_name_pattern("numpy")
        assert not is_internal_name_pattern("django")

    def test_short_generic_names_no_flag(self):
        """Short generic names shouldn't auto-flag."""
        assert not is_internal_name_pattern("utils")
        assert not is_internal_name_pattern("core")
        assert not is_internal_name_pattern("auth")

    def test_scoped_names(self):
        """Names with org-style prefixes are suspicious."""
        assert is_internal_name_pattern("myorg-ml-pipeline")
        assert is_internal_name_pattern("bigcorp-secrets-manager")


# ── Dependency confusion check ───────────────────────────────────


class TestDependencyConfusion:
    """Full dependency confusion detection."""

    def test_internal_name_on_pypi_flags(self):
        """Package matching internal pattern + exists on PyPI → flag."""
        result = check_dependency_confusion(
            "acme-internal-utils",
            internal_names={"acme-internal-utils"},
        )
        assert result is not None
        assert result["risk"] == "DEPENDENCY_CONFUSION"

    def test_internal_name_not_on_list_no_flag(self):
        """Package NOT in internal names list → no flag."""
        result = check_dependency_confusion(
            "requests",
            internal_names={"acme-internal-utils"},
        )
        assert result is None

    def test_empty_internal_names_uses_heuristic(self):
        """With no internal names list, use heuristic detection."""
        result = check_dependency_confusion(
            "mycompany-secret-service",
            internal_names=set(),
        )
        assert result is not None
        assert result["risk"] == "DEPENDENCY_CONFUSION_HEURISTIC"

    def test_public_package_no_heuristic_flag(self):
        """Known public package should not trigger heuristic."""
        result = check_dependency_confusion(
            "requests",
            internal_names=set(),
        )
        assert result is None

    def test_case_insensitive_matching(self):
        """Internal names matching should be case-insensitive."""
        result = check_dependency_confusion(
            "Acme-Internal-Utils",
            internal_names={"acme-internal-utils"},
        )
        assert result is not None

    def test_underscore_hyphen_normalized(self):
        """acme_internal_utils should match acme-internal-utils."""
        result = check_dependency_confusion(
            "acme_internal_utils",
            internal_names={"acme-internal-utils"},
        )
        assert result is not None

    def test_result_structure(self):
        """Result should contain expected fields."""
        result = check_dependency_confusion(
            "acme-internal-utils",
            internal_names={"acme-internal-utils"},
        )
        assert result is not None
        assert "risk" in result
        assert "package" in result
        assert "reason" in result


# ── CLI integration ──────────────────────────────────────────────


class TestAuditInternalNames:
    """audit command accepts --internal-names for confusion detection."""

    def test_audit_accepts_internal_names(self):
        """--internal-names should be valid for audit."""
        from click.testing import CliRunner

        from chaincanary.cli import main

        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", "nonexistent.txt",
            "--internal-names", "acme-utils,acme-auth",
        ])
        assert "No such option" not in (result.output or "")

    def test_check_accepts_internal_names(self):
        """--internal-names should also work for check."""
        from click.testing import CliRunner

        from chaincanary.cli import main

        runner = CliRunner()
        result = runner.invoke(main, [
            "check", "fakepkg==1.0.0",
            "--internal-names", "acme-utils",
            "--offline", "--local", __file__,
        ])
        assert "No such option" not in (result.output or "")


# ── Engine integration ───────────────────────────────────────────


class TestEngineDepConfusion:
    """AnalysisEngine passes internal_names and generates findings."""

    def test_engine_accepts_internal_names(self):
        from chaincanary.engine import AnalysisEngine

        engine = AnalysisEngine(
            internal_names={"acme-internal-utils"},
        )
        assert engine.internal_names == {"acme-internal-utils"}

    def test_engine_default_empty_internal_names(self):
        from chaincanary.engine import AnalysisEngine

        engine = AnalysisEngine()
        assert engine.internal_names == set()

    @patch("chaincanary.engine.download_wheel", return_value=None)
    @patch("chaincanary.engine.check_typosquatting", return_value=None)
    @patch(
        "chaincanary.engine.check_dependency_confusion",
        return_value={
            "risk": "DEPENDENCY_CONFUSION",
            "package": "acme-internal-utils",
            "reason": "Matches declared internal package name",
        },
    )
    def test_engine_generates_confusion_finding(
        self, mock_confusion, mock_typo, mock_download,
    ):
        from chaincanary.engine import AnalysisEngine

        engine = AnalysisEngine(
            internal_names={"acme-internal-utils"},
        )
        report = engine.analyze("acme-internal-utils", "1.0.0")
        confusion_findings = [
            f for f in report.findings
            if f.rule_id == "DEPENDENCY_CONFUSION"
        ]
        assert len(confusion_findings) >= 1
        assert confusion_findings[0].severity in (
            Severity.HIGH, Severity.CRITICAL,
        )
