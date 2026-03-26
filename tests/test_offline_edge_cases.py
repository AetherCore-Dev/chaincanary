"""
Edge case tests for --offline mode.

Covers: name normalization, corrupted wheels, empty dirs, combos with
SARIF/JSON output, unpinned versions, typosquatting in offline, and more.
"""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner

from chaincanary.cli import main


# ── Helpers ──────────────────────────────────────────────────────────


def _clean_wheel(
    directory: Path,
    name: str = "safe_pkg",
    version: str = "1.0.0",
) -> Path:
    """Create a minimal clean .whl file."""
    whl_name = f"{name}-{version}-py3-none-any.whl"
    whl_path = directory / whl_name
    with zipfile.ZipFile(whl_path, "w") as zf:
        zf.writestr(f"{name}/__init__.py", "# clean\n")
        zf.writestr(
            f"{name}-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n",
        )
        zf.writestr(f"{name}-{version}.dist-info/RECORD", "")
    return whl_path


def _run(args: list[str]) -> CliRunner.result_class:
    return CliRunner().invoke(main, args)


# ── Name normalization (hyphen vs underscore) ─────────────────────────


class TestNameNormalization:
    def test_requirements_hyphen_wheel_underscore(self, tmp_path):
        """my-pkg in requirements matches my_pkg wheel."""
        wd = tmp_path / "wheels"
        wd.mkdir()
        _clean_wheel(wd, "my_pkg", "1.0.0")

        req = tmp_path / "requirements.txt"
        req.write_text("my-pkg==1.0.0\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--json-output",
        ])
        data = json.loads(result.output)
        verdicts = [r["verdict"] for r in data["results"]]
        assert "UNKNOWN" not in verdicts

    def test_requirements_underscore_wheel_hyphen(self, tmp_path):
        """my_pkg in requirements matches my-pkg wheel."""
        wd = tmp_path / "wheels"
        wd.mkdir()
        _clean_wheel(wd, "my-pkg", "1.0.0")

        req = tmp_path / "requirements.txt"
        req.write_text("my_pkg==1.0.0\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--json-output",
        ])
        data = json.loads(result.output)
        verdicts = [r["verdict"] for r in data["results"]]
        assert "UNKNOWN" not in verdicts


# ── Subdirectory wheels not found (flat glob) ─────────────────────────


class TestSubdirectoryWheels:
    def test_wheels_in_subdir_not_found(self, tmp_path):
        wd = tmp_path / "wheels"
        subdir = wd / "subdir"
        subdir.mkdir(parents=True)
        _clean_wheel(subdir, "pkg_a", "1.0.0")

        req = tmp_path / "requirements.txt"
        req.write_text("pkg-a==1.0.0\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--json-output",
        ])
        data = json.loads(result.output)
        assert data["results"][0]["verdict"] == "UNKNOWN"


# ── Empty wheel directory ────────────────────────────────────────────


class TestEmptyWheelDir:
    def test_all_packages_unknown(self, tmp_path):
        wd = tmp_path / "wheels"
        wd.mkdir()

        req = tmp_path / "requirements.txt"
        req.write_text("pkg-a==1.0.0\npkg-b==2.0.0\npkg-c==3.0.0\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--json-output",
        ])
        data = json.loads(result.output)
        assert all(r["verdict"] == "UNKNOWN" for r in data["results"])

    def test_exit_code_zero_when_all_unknown(self, tmp_path):
        """UNKNOWN is not MALICIOUS or HIGH_RISK — exit 0."""
        wd = tmp_path / "wheels"
        wd.mkdir()

        req = tmp_path / "requirements.txt"
        req.write_text("pkg-a==1.0.0\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
        ])
        assert result.exit_code == 0

    def test_offline_no_wheel_finding_present(self, tmp_path):
        wd = tmp_path / "wheels"
        wd.mkdir()

        req = tmp_path / "requirements.txt"
        req.write_text("pkg-a==1.0.0\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--json-output",
        ])
        data = json.loads(result.output)
        findings = data["results"][0]["findings"]
        assert any(f["rule_id"] == "OFFLINE_NO_WHEEL" for f in findings)


# ── Corrupted wheel ──────────────────────────────────────────────────


class TestCorruptedWheel:
    def test_check_offline_corrupted_wheel_no_crash(self, tmp_path):
        bad_whl = tmp_path / "bad_pkg-1.0.0-py3-none-any.whl"
        bad_whl.write_bytes(b"this is not a zip file")

        result = _run([
            "check", "bad_pkg==1.0.0", "--offline",
            "--local", str(bad_whl),
        ])
        # Should not crash with unhandled exception
        # May exit 0 (if treated as safe) or 1 (if error finding)
        assert result.exit_code in (0, 1)
        assert result.exception is None


# ── Multiple platform wheels ──────────────────────────────────────────


class TestMultiplePlatformWheels:
    def test_same_version_different_platforms_one_result(self, tmp_path):
        wd = tmp_path / "wheels"
        wd.mkdir()

        # Create two wheels for same package/version, different platform
        for platform in ["py3-none-any", "cp311-cp311-linux_x86_64"]:
            whl_name = f"pkg_a-1.0.0-{platform}.whl"
            whl_path = wd / whl_name
            with zipfile.ZipFile(whl_path, "w") as zf:
                zf.writestr("pkg_a/__init__.py", "# clean\n")
                zf.writestr(
                    "pkg_a-1.0.0.dist-info/METADATA",
                    "Name: pkg-a\nVersion: 1.0.0\n",
                )
                zf.writestr("pkg_a-1.0.0.dist-info/RECORD", "")

        req = tmp_path / "requirements.txt"
        req.write_text("pkg-a==1.0.0\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--json-output",
        ])
        data = json.loads(result.output)
        # Should have exactly one result for pkg-a
        pkg_results = [r for r in data["results"] if r["package"] == "pkg-a"]
        assert len(pkg_results) == 1


# ── Unpinned versions in offline mode ─────────────────────────────────


class TestUnpinnedVersionsOffline:
    def test_unpinned_version_resolved_from_wheel_dir(self, tmp_path):
        wd = tmp_path / "wheels"
        wd.mkdir()
        _clean_wheel(wd, "mylib", "2.5.0")

        req = tmp_path / "requirements.txt"
        req.write_text("mylib\n")  # no version pin

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--json-output",
        ])
        data = json.loads(result.output)
        # Should find the wheel and scan it
        r = data["results"][0]
        assert r["version"] == "2.5.0"
        assert r["verdict"] != "UNKNOWN"

    def test_unpinned_no_matching_wheel_returns_unknown(self, tmp_path):
        wd = tmp_path / "wheels"
        wd.mkdir()

        req = tmp_path / "requirements.txt"
        req.write_text("mylib\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--json-output",
        ])
        data = json.loads(result.output)
        assert data["results"][0]["verdict"] == "UNKNOWN"


# ── Typosquatting in offline mode ─────────────────────────────────────


class TestTyposquattingOffline:
    def test_typosquatting_detected_in_offline_no_wheel(self, tmp_path):
        """H-2 fix: typosquatting check runs even without a wheel."""
        wd = tmp_path / "wheels"
        wd.mkdir()

        req = tmp_path / "requirements.txt"
        req.write_text("reqeusts==1.0.0\n")  # typo of requests

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--json-output",
        ])
        data = json.loads(result.output)
        findings = data["results"][0]["findings"]
        rule_ids = [f["rule_id"] for f in findings]
        assert "TYPOSQUATTING" in rule_ids

    def test_typosquatting_and_offline_no_wheel_both_present(self, tmp_path):
        """Both TYPOSQUATTING and OFFLINE_NO_WHEEL findings coexist."""
        wd = tmp_path / "wheels"
        wd.mkdir()

        req = tmp_path / "requirements.txt"
        req.write_text("reqeusts==1.0.0\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--json-output",
        ])
        data = json.loads(result.output)
        findings = data["results"][0]["findings"]
        rule_ids = {f["rule_id"] for f in findings}
        assert "TYPOSQUATTING" in rule_ids
        assert "OFFLINE_NO_WHEEL" in rule_ids

    def test_exact_package_name_no_typosquatting(self, tmp_path):
        """requests (exact) should NOT be flagged as typosquatting."""
        wd = tmp_path / "wheels"
        wd.mkdir()

        req = tmp_path / "requirements.txt"
        req.write_text("requests==2.28.0\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--json-output",
        ])
        data = json.loads(result.output)
        findings = data["results"][0]["findings"]
        rule_ids = [f["rule_id"] for f in findings]
        assert "TYPOSQUATTING" not in rule_ids


# ── Offline + SARIF output ────────────────────────────────────────────


class TestOfflineSarifOutput:
    def test_audit_offline_sarif_with_found_wheels(self, tmp_path):
        wd = tmp_path / "wheels"
        wd.mkdir()
        _clean_wheel(wd, "safe_pkg", "1.0.0")

        req = tmp_path / "requirements.txt"
        req.write_text("safe-pkg==1.0.0\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--sarif-output",
        ])
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data

    def test_audit_offline_sarif_with_missing_wheels(self, tmp_path):
        wd = tmp_path / "wheels"
        wd.mkdir()

        req = tmp_path / "requirements.txt"
        req.write_text("missing-pkg==1.0.0\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--sarif-output",
        ])
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"
        # OFFLINE_NO_WHEEL finding should be in SARIF
        results = data["runs"][0]["results"]
        assert any(r["ruleId"] == "OFFLINE_NO_WHEEL" for r in results)


# ── Mixed found and missing wheels ───────────────────────────────────


class TestMixedWheels:
    def test_audit_offline_mixed_found_and_missing(self, tmp_path):
        wd = tmp_path / "wheels"
        wd.mkdir()
        _clean_wheel(wd, "found_pkg", "1.0.0")

        req = tmp_path / "requirements.txt"
        req.write_text("found-pkg==1.0.0\nmissing-pkg==2.0.0\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--json-output",
        ])
        data = json.loads(result.output)
        assert len(data["results"]) == 2

        by_name = {r["package"]: r for r in data["results"]}
        assert by_name["found-pkg"]["verdict"] != "UNKNOWN"
        assert by_name["missing-pkg"]["verdict"] == "UNKNOWN"

    def test_fail_on_high_risk_ignores_unknown(self, tmp_path):
        """--fail-on HIGH_RISK should not fail for UNKNOWN packages."""
        wd = tmp_path / "wheels"
        wd.mkdir()

        req = tmp_path / "requirements.txt"
        req.write_text("missing-pkg==1.0.0\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--fail-on", "HIGH_RISK",
        ])
        assert result.exit_code == 0


# ── Non-standard wheel filenames ──────────────────────────────────────


class TestNonStandardWheelFilename:
    def test_wheel_with_no_version_in_name_skipped(self, tmp_path):
        wd = tmp_path / "wheels"
        wd.mkdir()
        # Create a wheel with non-standard name (no version separator)
        bad_whl = wd / "mypkg.whl"
        with zipfile.ZipFile(bad_whl, "w") as zf:
            zf.writestr("mypkg/__init__.py", "")
            zf.writestr("mypkg-1.0.dist-info/METADATA", "Name: mypkg\n")

        req = tmp_path / "requirements.txt"
        req.write_text("mypkg==1.0.0\n")

        result = _run([
            "audit", str(req), "--offline", "--wheel-dir", str(wd),
            "--json-output",
        ])
        data = json.loads(result.output)
        # Non-standard name should not match — returns UNKNOWN
        assert data["results"][0]["verdict"] == "UNKNOWN"
