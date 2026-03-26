"""
Tests for --skip flag support in audit command.

--skip allows users to ignore known-safe packages during audit
(e.g., --skip torch,tensorflow to speed up large lockfile scans).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from chaincanary.cli import main


@pytest.fixture()
def sample_requirements(tmp_path):
    """Create a sample requirements.txt with several packages."""
    req_file = tmp_path / "requirements.txt"
    req_file.write_text(
        "requests==2.31.0\n"
        "torch==2.1.0\n"
        "tensorflow==2.15.0\n"
        "click==8.1.7\n"
        "flask==3.0.0\n"
    )
    return req_file


def _make_mock_engine():
    """Create a mock AnalysisEngine that returns SAFE for everything."""
    mock_engine = MagicMock()
    mock_report = MagicMock()
    mock_report.score = 0
    mock_report.verdict = "SAFE"
    mock_report.safe_version = None
    mock_report.findings = []
    mock_engine.analyze.return_value = mock_report
    return mock_engine


class TestAuditSkipFlag:
    """audit command accepts --skip to exclude packages."""

    def test_audit_accepts_skip_flag(self, sample_requirements):
        """--skip should be a valid option for audit."""
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", str(sample_requirements),
            "--skip", "torch,tensorflow",
            "--offline",
        ])
        # Should not fail with "No such option: --skip"
        assert "No such option" not in (result.output or "")

    @patch("chaincanary.cli.AnalysisEngine")
    def test_skip_excludes_packages(
        self, mock_engine_cls, sample_requirements,
    ):
        """Skipped packages should not be scanned at all."""
        mock_engine_cls.return_value = _make_mock_engine()

        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", str(sample_requirements),
            "--skip", "torch,tensorflow",
            "--json-output",
        ])

        output = json.loads(result.output)
        scanned = [r["package"] for r in output["results"]]

        assert "torch" not in scanned
        assert "tensorflow" not in scanned
        assert "requests" in scanned
        assert "click" in scanned
        assert "flask" in scanned

    @patch("chaincanary.cli.AnalysisEngine")
    def test_skip_case_insensitive(
        self, mock_engine_cls, sample_requirements,
    ):
        """--skip should be case-insensitive."""
        mock_engine_cls.return_value = _make_mock_engine()

        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", str(sample_requirements),
            "--skip", "Torch,TENSORFLOW",
            "--json-output",
        ])

        output = json.loads(result.output)
        scanned = [r["package"] for r in output["results"]]
        assert "torch" not in scanned
        assert "tensorflow" not in scanned

    @patch("chaincanary.cli.AnalysisEngine")
    def test_skip_with_spaces(
        self, mock_engine_cls, sample_requirements,
    ):
        """--skip should handle spaces around commas."""
        mock_engine_cls.return_value = _make_mock_engine()

        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", str(sample_requirements),
            "--skip", "torch , tensorflow",
            "--json-output",
        ])

        output = json.loads(result.output)
        scanned = [r["package"] for r in output["results"]]
        assert "torch" not in scanned
        assert "tensorflow" not in scanned

    def test_skip_empty_string_skips_nothing(self, sample_requirements):
        """--skip '' should not skip any packages."""
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", str(sample_requirements),
            "--skip", "",
            "--offline",
        ])
        assert "No such option" not in (result.output or "")

    @patch("chaincanary.cli.AnalysisEngine")
    def test_skip_shows_skipped_count(
        self, mock_engine_cls, sample_requirements,
    ):
        """Audit should report how many packages were skipped."""
        mock_engine_cls.return_value = _make_mock_engine()

        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", str(sample_requirements),
            "--skip", "torch,tensorflow",
        ])

        assert "skipped" in result.output.lower()

    @patch("chaincanary.cli.AnalysisEngine")
    def test_skip_json_output_includes_metadata(
        self, mock_engine_cls, sample_requirements,
    ):
        """JSON output should include skip metadata."""
        mock_engine_cls.return_value = _make_mock_engine()

        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", str(sample_requirements),
            "--skip", "torch,tensorflow",
            "--json-output",
        ])

        output = json.loads(result.output)
        assert "skipped" in output
        skipped = [s.lower() for s in output["skipped"]]
        assert "torch" in skipped
        assert "tensorflow" in skipped


class TestCheckSkipNotApplicable:
    """--skip should NOT be on check/install (only audit)."""

    def test_check_does_not_have_skip(self):
        """check command should not have --skip."""
        runner = CliRunner()
        result = runner.invoke(main, [
            "check", "fakepkg==1.0.0", "--skip", "something",
        ])
        assert "No such option" in (result.output or "")

    def test_install_does_not_have_skip(self):
        """install command should not have --skip."""
        runner = CliRunner()
        result = runner.invoke(main, [
            "install", "fakepkg==1.0.0", "--skip", "something",
        ])
        assert "No such option" in (result.output or "")
