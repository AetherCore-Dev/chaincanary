"""Tests for the chaincanary pre-commit hook."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from chaincanary.models import Finding, RiskReport, Severity
from chaincanary.pre_commit import main


def _make_report(
    package: str,
    version: str,
    verdict: str = "SAFE",
    score: float = 0.0,
) -> RiskReport:
    """Create a RiskReport with the given verdict/score."""
    report = RiskReport(package=package, version=version)
    report.verdict = verdict
    report.score = score
    return report


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture()
def clean_lockfile(tmp_path: Path) -> Path:
    p = tmp_path / "requirements.txt"
    p.write_text("requests==2.31.0\nclick==8.1.7\n")
    return p


@pytest.fixture()
def malicious_lockfile(tmp_path: Path) -> Path:
    p = tmp_path / "requirements.txt"
    p.write_text("evil-pkg==1.0.0\nrequests==2.31.0\n")
    return p


class TestPreCommitClean:
    """Hook exits 0 for clean packages."""

    @patch("chaincanary.pre_commit.AnalysisEngine")
    def test_clean_lockfile_exits_zero(
        self, mock_engine_cls, runner: CliRunner, clean_lockfile: Path
    ):
        engine = mock_engine_cls.return_value
        engine.analyze.side_effect = lambda pkg, ver: _make_report(pkg, ver, "SAFE", 0.0)

        result = runner.invoke(main, [str(clean_lockfile)])
        assert result.exit_code == 0

    @patch("chaincanary.pre_commit.AnalysisEngine")
    def test_no_matching_files_exits_zero(self, mock_engine_cls, runner: CliRunner, tmp_path: Path):
        """Non-lockfile filenames are silently ignored."""
        other = tmp_path / "README.md"
        other.write_text("# hello")

        result = runner.invoke(main, [str(other)])
        assert result.exit_code == 0
        mock_engine_cls.return_value.analyze.assert_not_called()

    def test_no_files_exits_zero(self, runner: CliRunner):
        result = runner.invoke(main, [])
        assert result.exit_code == 0


class TestPreCommitBlocking:
    """Hook exits 1 when a package hits the fail-on threshold."""

    @patch("chaincanary.pre_commit.AnalysisEngine")
    def test_blocks_malicious(
        self, mock_engine_cls, runner: CliRunner, malicious_lockfile: Path
    ):
        engine = mock_engine_cls.return_value

        def _analyze(pkg, ver):
            if pkg == "evil-pkg":
                return _make_report(pkg, ver, "MALICIOUS", 9.0)
            return _make_report(pkg, ver, "SAFE", 0.0)

        engine.analyze.side_effect = _analyze

        result = runner.invoke(main, [str(malicious_lockfile)])
        assert result.exit_code == 1
        assert "evil-pkg" in result.output

    @patch("chaincanary.pre_commit.AnalysisEngine")
    def test_respects_fail_on_high_risk(
        self, mock_engine_cls, runner: CliRunner, malicious_lockfile: Path
    ):
        engine = mock_engine_cls.return_value

        def _analyze(pkg, ver):
            if pkg == "evil-pkg":
                return _make_report(pkg, ver, "HIGH_RISK", 5.0)
            return _make_report(pkg, ver, "SAFE", 0.0)

        engine.analyze.side_effect = _analyze

        # Default --fail-on MALICIOUS: HIGH_RISK should pass
        result = runner.invoke(main, [str(malicious_lockfile)])
        assert result.exit_code == 0

        # Explicit --fail-on HIGH_RISK: should block
        result = runner.invoke(main, [str(malicious_lockfile), "--fail-on", "HIGH_RISK"])
        assert result.exit_code == 1
        assert "evil-pkg" in result.output

    @patch("chaincanary.pre_commit.AnalysisEngine")
    def test_output_includes_package_name_and_verdict(
        self, mock_engine_cls, runner: CliRunner, malicious_lockfile: Path
    ):
        engine = mock_engine_cls.return_value

        def _analyze(pkg, ver):
            if pkg == "evil-pkg":
                return _make_report(pkg, ver, "MALICIOUS", 9.5)
            return _make_report(pkg, ver, "SAFE", 0.0)

        engine.analyze.side_effect = _analyze

        result = runner.invoke(main, [str(malicious_lockfile)])
        assert "evil-pkg" in result.output
        assert "MALICIOUS" in result.output
        assert "supply-chain risk detected" in result.output


class TestPreCommitMultipleFiles:
    """Hook handles multiple lockfiles in a single invocation."""

    @patch("chaincanary.pre_commit.AnalysisEngine")
    def test_multiple_files(self, mock_engine_cls, runner: CliRunner, tmp_path: Path):
        req1 = tmp_path / "requirements.txt"
        req1.write_text("clean==1.0.0\n")
        req2 = tmp_path / "requirements-dev.txt"
        req2.write_text("bad-pkg==0.1.0\n")

        engine = mock_engine_cls.return_value

        def _analyze(pkg, ver):
            if pkg == "bad-pkg":
                return _make_report(pkg, ver, "MALICIOUS", 8.0)
            return _make_report(pkg, ver, "SAFE", 0.0)

        engine.analyze.side_effect = _analyze

        result = runner.invoke(main, [str(req1), str(req2)])
        assert result.exit_code == 1
        assert "bad-pkg" in result.output


class TestPreCommitSkip:
    """Hook --skip flag excludes packages from scanning."""

    @patch("chaincanary.pre_commit.AnalysisEngine")
    def test_skip_flag_excludes_package(
        self, mock_engine_cls, runner: CliRunner, malicious_lockfile: Path
    ):
        engine = mock_engine_cls.return_value

        def _analyze(pkg, ver):
            if pkg == "evil-pkg":
                return _make_report(pkg, ver, "MALICIOUS", 9.0)
            return _make_report(pkg, ver, "SAFE", 0.0)

        engine.analyze.side_effect = _analyze

        result = runner.invoke(main, [str(malicious_lockfile), "--skip", "evil-pkg"])
        assert result.exit_code == 0

    @patch("chaincanary.pre_commit.AnalysisEngine")
    def test_skip_is_case_insensitive(
        self, mock_engine_cls, runner: CliRunner, malicious_lockfile: Path
    ):
        engine = mock_engine_cls.return_value

        def _analyze(pkg, ver):
            if pkg == "evil-pkg":
                return _make_report(pkg, ver, "MALICIOUS", 9.0)
            return _make_report(pkg, ver, "SAFE", 0.0)

        engine.analyze.side_effect = _analyze

        result = runner.invoke(main, [str(malicious_lockfile), "--skip", "Evil-Pkg"])
        assert result.exit_code == 0


class TestPreCommitEngineConfig:
    """Hook configures the engine correctly."""

    @patch("chaincanary.pre_commit.AnalysisEngine")
    def test_skip_dynamic_always_true(
        self, mock_engine_cls, runner: CliRunner, clean_lockfile: Path
    ):
        engine = mock_engine_cls.return_value
        engine.analyze.return_value = _make_report("requests", "2.31.0")

        runner.invoke(main, [str(clean_lockfile)])

        mock_engine_cls.assert_called_once_with(skip_dynamic=True, timeout=30)

    @patch("chaincanary.pre_commit.AnalysisEngine")
    def test_custom_timeout(
        self, mock_engine_cls, runner: CliRunner, clean_lockfile: Path
    ):
        engine = mock_engine_cls.return_value
        engine.analyze.return_value = _make_report("requests", "2.31.0")

        runner.invoke(main, [str(clean_lockfile), "--timeout", "60"])

        mock_engine_cls.assert_called_once_with(skip_dynamic=True, timeout=60)
