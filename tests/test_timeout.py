"""
Tests for --timeout flag support across CLI, engine, and downloader.

TDD RED phase: These tests define the expected behavior before implementation.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from chaincanary.cli import main
from chaincanary.downloader import download_wheel, get_all_versions, get_latest_safe_version
from chaincanary.engine import AnalysisEngine

# ── Downloader: timeout parameter acceptance ─────────────────────────


class TestDownloaderTimeout:
    """download_wheel and friends accept a timeout parameter."""

    @patch("chaincanary.downloader._make_session")
    def test_download_wheel_accepts_timeout(self, mock_session_factory):
        """download_wheel should accept and use a custom timeout."""
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_session.get.return_value = mock_resp
        mock_session_factory.return_value = mock_session

        download_wheel("fakepkg", "1.0.0", timeout=10)

        # The metadata request should use the custom timeout
        call_args = mock_session.get.call_args
        assert call_args.kwargs.get("timeout") == 10 or call_args[1].get("timeout") == 10

    @patch("chaincanary.downloader._make_session")
    def test_download_wheel_default_timeout(self, mock_session_factory):
        """download_wheel should use 30s default when timeout not specified."""
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_session.get.return_value = mock_resp
        mock_session_factory.return_value = mock_session

        download_wheel("fakepkg", "1.0.0")

        call_args = mock_session.get.call_args
        assert call_args.kwargs.get("timeout") == 30 or call_args[1].get("timeout") == 30

    @patch("chaincanary.downloader._make_session")
    def test_get_all_versions_accepts_timeout(self, mock_session_factory):
        """get_all_versions should accept and use a custom timeout."""
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"releases": {"1.0": []}}
        mock_session.get.return_value = mock_resp
        mock_session_factory.return_value = mock_session

        result = get_all_versions("fakepkg", timeout=5)

        call_args = mock_session.get.call_args
        assert call_args.kwargs.get("timeout") == 5 or call_args[1].get("timeout") == 5
        assert result == ["1.0"]

    @patch("chaincanary.downloader._make_session")
    def test_get_latest_safe_version_accepts_timeout(self, mock_session_factory):
        """get_latest_safe_version should accept and use a custom timeout."""
        mock_session = MagicMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"releases": {"0.9.0": [], "1.0.0": []}}
        mock_session.get.return_value = mock_resp
        mock_session_factory.return_value = mock_session

        get_latest_safe_version("fakepkg", "1.0.0", timeout=8)

        call_args = mock_session.get.call_args
        assert call_args.kwargs.get("timeout") == 8 or call_args[1].get("timeout") == 8


# ── Engine: timeout threading ────────────────────────────────────────


class TestEngineTimeout:
    """AnalysisEngine stores and passes timeout to downloader."""

    def test_engine_accepts_timeout(self):
        """AnalysisEngine constructor should accept a timeout parameter."""
        engine = AnalysisEngine(timeout=10)
        assert engine.timeout == 10

    def test_engine_default_timeout(self):
        """AnalysisEngine should default to 30s timeout."""
        engine = AnalysisEngine()
        assert engine.timeout == 30

    @patch("chaincanary.engine.download_wheel")
    @patch("chaincanary.engine.check_typosquatting", return_value=None)
    def test_engine_passes_timeout_to_downloader(self, _mock_typo, mock_download):
        """Engine.analyze should pass timeout to download_wheel."""
        mock_download.return_value = None  # simulate download failure

        engine = AnalysisEngine(timeout=15, offline=False)
        engine.analyze("fakepkg", "1.0.0")

        mock_download.assert_called_once()
        call_kwargs = mock_download.call_args.kwargs
        assert call_kwargs.get("timeout") == 15


# ── CLI: --timeout option ────────────────────────────────────────────


class TestCLITimeout:
    """CLI commands expose --timeout flag."""

    def test_check_accepts_timeout_flag(self):
        """'check' command should accept --timeout."""
        runner = CliRunner()
        # Use --offline + --local to avoid real network calls
        # The flag should be accepted without error
        result = runner.invoke(main, [
            "check", "fakepkg==1.0.0",
            "--timeout", "10",
            "--offline",
            "--local", __file__,  # use this test file as a dummy
        ])
        # Should not fail with "No such option: --timeout"
        assert "No such option" not in (result.output or "")
        assert "--timeout" not in (result.output or "") or "No such option" not in (result.output or "")

    def test_install_accepts_timeout_flag(self):
        """'install' command should accept --timeout."""
        runner = CliRunner()
        result = runner.invoke(main, [
            "install", "fakepkg==1.0.0",
            "--timeout", "10",
            "--json-output",
        ])
        # Should not fail with "No such option: --timeout"
        assert "No such option" not in (result.output or "")

    def test_audit_accepts_timeout_flag(self):
        """'audit' command should accept --timeout."""
        runner = CliRunner()
        result = runner.invoke(main, [
            "audit", "nonexistent.txt",
            "--timeout", "10",
        ])
        # Should not fail with "No such option: --timeout"
        assert "No such option" not in (result.output or "")

    def test_check_timeout_default_is_30(self):
        """When --timeout is not specified, default should be 30."""
        runner = CliRunner()
        with patch("chaincanary.cli._run_analysis") as mock_run:
            mock_report = MagicMock()
            mock_report.score = 0
            mock_report.verdict = "SAFE"
            mock_report.is_blocked = False
            mock_report.safe_version = None
            mock_report.findings = []
            mock_report.behavior_diff = None
            mock_run.return_value = mock_report

            runner.invoke(main, [
                "check", "fakepkg==1.0.0",
                "--offline",
                "--local", __file__,
            ])
            call_kwargs = mock_run.call_args.kwargs if mock_run.call_args else {}
            assert call_kwargs.get("timeout") == 30


# ── Timeout error handling ───────────────────────────────────────────


class TestTimeoutErrorHandling:
    """Timeout errors produce clear user-facing messages."""

    @patch("chaincanary.downloader._make_session")
    def test_download_timeout_returns_none(self, mock_session_factory):
        """download_wheel should return None when request times out."""
        import requests

        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.Timeout("Connection timed out")
        mock_session_factory.return_value = mock_session

        result = download_wheel("fakepkg", "1.0.0", timeout=1)
        assert result is None

    @patch("chaincanary.downloader._make_session")
    def test_get_all_versions_timeout_returns_empty(self, mock_session_factory):
        """get_all_versions should return [] when request times out."""
        import requests

        mock_session = MagicMock()
        mock_session.get.side_effect = requests.exceptions.Timeout("Connection timed out")
        mock_session_factory.return_value = mock_session

        result = get_all_versions("fakepkg", timeout=1)
        assert result == []
