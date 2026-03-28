"""Tests for PyPI attestation verification (PEP 740)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from chaincanary.attestation import (
    AttestationResult,
    _normalize_package_name,
    _parse_attestation_response,
    attestation_to_findings,
    check_attestation,
)
from chaincanary.models import RiskReport, Severity


def _mock_streaming_response(status_code: int, body: dict | None = None):
    """Create a mock response that supports streaming (iter_content)."""
    resp = MagicMock()
    resp.status_code = status_code
    if body is not None:
        raw_bytes = json.dumps(body).encode()
        resp.iter_content = MagicMock(return_value=[raw_bytes])
    else:
        resp.iter_content = MagicMock(return_value=[])
    resp.close = MagicMock()
    return resp


# ── AttestationResult immutability ────────────────────────────────


class TestAttestationResult:
    def test_frozen_dataclass(self):
        r = AttestationResult(has_attestation=True, publisher_kind="github-actions")
        with pytest.raises(AttributeError):
            r.has_attestation = False  # type: ignore[misc]

    def test_defaults(self):
        r = AttestationResult(has_attestation=False)
        assert r.publisher_kind is None
        assert r.repository is None
        assert r.workflow_ref is None
        assert r.error is None


# ── _normalize_package_name() ─────────────────────────────────────


class TestNormalizePackageName:
    def test_lowercase(self):
        assert _normalize_package_name("MyPackage") == "mypackage"

    def test_underscore_to_hyphen(self):
        assert _normalize_package_name("my_package") == "my-package"

    def test_dots_to_hyphen(self):
        assert _normalize_package_name("my.package") == "my-package"

    def test_consecutive_separators(self):
        assert _normalize_package_name("my__package") == "my-package"

    def test_already_normalized(self):
        assert _normalize_package_name("requests") == "requests"


# ── Input validation ──────────────────────────────────────────────


class TestInputValidation:
    def test_invalid_package_name_rejected(self):
        result = check_attestation("pkg/../evil", "1.0.0", "file.whl")
        assert result.has_attestation is False
        assert result.error == "Invalid package name"

    def test_invalid_version_rejected(self):
        result = check_attestation("pkg", "1.0/../../evil", "file.whl")
        assert result.has_attestation is False
        assert result.error == "Invalid version string"

    def test_invalid_filename_rejected(self):
        result = check_attestation("pkg", "1.0.0", "../../../etc/passwd")
        assert result.has_attestation is False
        assert result.error == "Invalid filename"

    def test_valid_pep440_version_accepted(self):
        # Should not fail validation (will fail at network, but that's ok)
        with patch("chaincanary.attestation.requests.get") as mock_get:
            mock_get.return_value = _mock_streaming_response(404)
            result = check_attestation(
                "pkg", "1.0.0a1+local", "pkg-1.0.0a1-py3-none-any.whl",
            )
            assert result.error is None  # No validation error

    def test_empty_package_name_rejected(self):
        result = check_attestation("", "1.0.0", "file.whl")
        assert result.error == "Invalid package name"


# ── check_attestation() ──────────────────────────────────────────


class TestCheckAttestation:
    @patch("chaincanary.attestation.requests.get")
    def test_200_with_github_attestation(self, mock_get):
        body = {
            "attestation_bundles": [
                {
                    "publisher": {
                        "kind": "github-actions",
                        "claims": {
                            "repository": "owner/repo",
                            "workflow_ref": (
                                "owner/repo/.github/workflows/"
                                "publish.yml@refs/tags/v1.0"
                            ),
                        },
                    },
                    "verification_material": {},
                }
            ]
        }
        mock_get.return_value = _mock_streaming_response(200, body)
        result = check_attestation("pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl")
        assert result.has_attestation is True
        assert result.publisher_kind == "github-actions"
        assert result.repository == "owner/repo"
        assert result.workflow_ref is not None
        assert result.error is None

    @patch("chaincanary.attestation.requests.get")
    def test_404_no_attestation(self, mock_get):
        mock_get.return_value = _mock_streaming_response(404)
        result = check_attestation("pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl")
        assert result.has_attestation is False
        assert result.error is None

    @patch("chaincanary.attestation.requests.get")
    def test_connection_error_sanitized(self, mock_get):
        mock_get.side_effect = ConnectionError("DNS failure")
        result = check_attestation("pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl")
        assert result.has_attestation is False
        assert result.error == "Network error"

    @patch("chaincanary.attestation.requests.get")
    def test_500_error_captured(self, mock_get):
        mock_get.return_value = _mock_streaming_response(500)
        result = check_attestation("pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl")
        assert result.has_attestation is False
        assert "500" in (result.error or "")

    @patch("chaincanary.attestation.requests.get")
    def test_invalid_json_captured(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        resp.iter_content = MagicMock(return_value=[b"not json"])
        resp.close = MagicMock()
        mock_get.return_value = resp
        result = check_attestation("pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl")
        assert result.has_attestation is False
        assert "Invalid JSON" in (result.error or "")

    @patch("chaincanary.attestation.requests.get")
    def test_empty_bundles_no_attestation(self, mock_get):
        mock_get.return_value = _mock_streaming_response(
            200, {"attestation_bundles": []},
        )
        result = check_attestation("pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl")
        assert result.has_attestation is False

    @patch("chaincanary.attestation.requests.get")
    def test_timeout_passed_to_request(self, mock_get):
        mock_get.return_value = _mock_streaming_response(404)
        check_attestation("pkg", "1.0.0", "file.whl", timeout=42)
        mock_get.assert_called_once()
        assert mock_get.call_args.kwargs["timeout"] == (10, 42)

    @patch("chaincanary.attestation.requests.get")
    def test_correct_url_and_headers(self, mock_get):
        mock_get.return_value = _mock_streaming_response(404)
        check_attestation(
            "requests", "2.31.0", "requests-2.31.0-py3-none-any.whl",
        )
        url = mock_get.call_args.args[0]
        headers = mock_get.call_args.kwargs["headers"]
        assert "requests" in url
        assert "2.31.0" in url
        assert "requests-2.31.0-py3-none-any.whl" in url
        assert headers["Accept"] == "application/vnd.pypi.integrity.v1+json"

    @patch("chaincanary.attestation.requests.get")
    def test_package_name_normalized_in_url(self, mock_get):
        mock_get.return_value = _mock_streaming_response(404)
        check_attestation(
            "My_Package", "1.0.0", "my_package-1.0.0-py3-none-any.whl",
        )
        url = mock_get.call_args.args[0]
        assert "/my-package/" in url

    @patch("chaincanary.attestation.requests.get")
    def test_gitlab_publisher(self, mock_get):
        body = {
            "attestation_bundles": [
                {
                    "publisher": {
                        "kind": "gitlab-ci",
                        "claims": {"repository": "group/project"},
                    },
                }
            ]
        }
        mock_get.return_value = _mock_streaming_response(200, body)
        result = check_attestation("pkg", "1.0.0", "file.whl")
        assert result.publisher_kind == "gitlab-ci"
        assert result.repository == "group/project"

    @patch("chaincanary.attestation.requests.get")
    def test_timeout_exception_sanitized(self, mock_get):
        import requests as req

        mock_get.side_effect = req.exceptions.Timeout("timed out")
        result = check_attestation("pkg", "1.0.0", "file.whl")
        assert result.has_attestation is False
        assert result.error == "Request timed out"

    @patch("chaincanary.attestation.requests.get")
    def test_response_too_large_rejected(self, mock_get):
        resp = MagicMock()
        resp.status_code = 200
        # Return chunks that exceed _MAX_RESPONSE_BYTES (1 MB)
        large_chunk = b"x" * (512 * 1024)  # 512 KB per chunk
        resp.iter_content = MagicMock(return_value=[large_chunk, large_chunk, large_chunk])
        resp.close = MagicMock()
        mock_get.return_value = resp
        result = check_attestation("pkg", "1.0.0", "pkg-1.0.0-py3-none-any.whl")
        assert result.has_attestation is False
        assert result.error == "Response too large"

    @patch("chaincanary.attestation.requests.get")
    def test_uses_streaming_mode(self, mock_get):
        mock_get.return_value = _mock_streaming_response(404)
        check_attestation("pkg", "1.0.0", "file.whl")
        assert mock_get.call_args.kwargs["stream"] is True


# ── attestation_to_findings() ────────────────────────────────────


class TestAttestationToFindings:
    def test_verified_produces_info_finding(self):
        result = AttestationResult(
            has_attestation=True,
            publisher_kind="github-actions",
            repository="owner/repo",
        )
        findings = attestation_to_findings(result, "pkg", "1.0.0")
        assert len(findings) == 1
        assert findings[0].rule_id == "ATTESTATION_VERIFIED"
        assert findings[0].severity == Severity.INFO
        assert findings[0].source == "attestation"
        assert "owner/repo" in findings[0].evidence

    def test_no_attestation_produces_info_finding(self):
        result = AttestationResult(has_attestation=False)
        findings = attestation_to_findings(result, "pkg", "1.0.0")
        assert len(findings) == 1
        assert findings[0].rule_id == "NO_ATTESTATION"
        assert findings[0].severity == Severity.INFO
        assert findings[0].source == "attestation"

    def test_error_produces_no_findings(self):
        result = AttestationResult(has_attestation=False, error="timeout")
        findings = attestation_to_findings(result, "pkg", "1.0.0")
        assert findings == []

    def test_verified_finding_does_not_affect_score(self):
        report = RiskReport(package="pkg", version="1.0.0")
        result = AttestationResult(
            has_attestation=True, publisher_kind="github-actions",
        )
        report.findings.extend(attestation_to_findings(result, "pkg", "1.0.0"))
        report.calculate_score()
        assert report.score == 0.0
        assert report.verdict == "SAFE"

    def test_no_attestation_finding_does_not_affect_score(self):
        report = RiskReport(package="pkg", version="1.0.0")
        result = AttestationResult(has_attestation=False)
        report.findings.extend(attestation_to_findings(result, "pkg", "1.0.0"))
        report.calculate_score()
        assert report.score == 0.0
        assert report.verdict == "SAFE"

    def test_verified_with_workflow_ref_in_evidence(self):
        result = AttestationResult(
            has_attestation=True,
            publisher_kind="github-actions",
            repository="owner/repo",
            workflow_ref="owner/repo/.github/workflows/publish.yml@refs/tags/v1.0",
        )
        findings = attestation_to_findings(result, "pkg", "1.0.0")
        assert "Workflow:" in findings[0].evidence

    def test_verified_without_repository(self):
        result = AttestationResult(
            has_attestation=True,
            publisher_kind="github-actions",
        )
        findings = attestation_to_findings(result, "pkg", "1.0.0")
        assert len(findings) == 1
        assert "Repository" not in findings[0].evidence

    def test_finding_description_includes_package_name(self):
        result = AttestationResult(has_attestation=False)
        findings = attestation_to_findings(result, "mypackage", "2.0.0")
        assert "mypackage==2.0.0" in findings[0].description


# ── _parse_attestation_response() ────────────────────────────────


class TestParseAttestationResponse:
    def test_missing_claims(self):
        data = {
            "attestation_bundles": [
                {"publisher": {"kind": "github-actions"}},
            ],
        }
        result = _parse_attestation_response(data)
        assert result.has_attestation is True
        assert result.publisher_kind == "github-actions"
        assert result.repository is None

    def test_missing_publisher(self):
        data = {"attestation_bundles": [{}]}
        result = _parse_attestation_response(data)
        assert result.has_attestation is True
        assert result.publisher_kind is None

    def test_multiple_bundles_uses_first(self):
        data = {
            "attestation_bundles": [
                {
                    "publisher": {
                        "kind": "github-actions",
                        "claims": {"repository": "a/b"},
                    },
                },
                {
                    "publisher": {
                        "kind": "gitlab-ci",
                        "claims": {"repository": "c/d"},
                    },
                },
            ],
        }
        result = _parse_attestation_response(data)
        assert result.repository == "a/b"
        assert result.publisher_kind == "github-actions"

    def test_empty_bundles(self):
        data = {"attestation_bundles": []}
        result = _parse_attestation_response(data)
        assert result.has_attestation is False

    def test_missing_bundles_key(self):
        data = {}
        result = _parse_attestation_response(data)
        assert result.has_attestation is False


# ── Engine integration tests ──────────────────────────────────────


class TestEngineAttestationIntegration:
    """Test that the engine correctly gates attestation checks."""

    @patch("chaincanary.engine.check_attestation")
    @patch("chaincanary.engine.download_wheel")
    def test_attestation_called_after_download(
        self, mock_download, mock_check, tmp_path,
    ):
        from chaincanary.engine import AnalysisEngine

        whl = tmp_path / "pkg-1.0.0-py3-none-any.whl"
        whl.write_bytes(b"PK\x03\x04")  # minimal zip header
        mock_download.return_value = whl
        mock_check.return_value = AttestationResult(
            has_attestation=True, publisher_kind="github-actions",
        )

        engine = AnalysisEngine(
            skip_dynamic=True, check_attestation_flag=True,
        )
        with patch.object(engine.static, "analyze_wheel", return_value=[]):
            report = engine.analyze("pkg", "1.0.0")

        mock_check.assert_called_once()
        att = [f for f in report.findings if f.source == "attestation"]
        assert len(att) == 1
        assert att[0].rule_id == "ATTESTATION_VERIFIED"

    @patch("chaincanary.engine.check_attestation")
    def test_attestation_skipped_offline(self, mock_check, tmp_path):
        from chaincanary.engine import AnalysisEngine

        engine = AnalysisEngine(
            skip_dynamic=True, offline=True,
            check_attestation_flag=True,
        )
        # Offline without local_wheel returns early
        report = engine.analyze("pkg", "1.0.0")
        mock_check.assert_not_called()

    @patch("chaincanary.engine.check_attestation")
    @patch("chaincanary.engine.download_wheel")
    def test_attestation_skipped_local_wheel(
        self, mock_download, mock_check, tmp_path,
    ):
        from chaincanary.engine import AnalysisEngine

        whl = tmp_path / "pkg-1.0.0-py3-none-any.whl"
        whl.write_bytes(b"PK\x03\x04")

        engine = AnalysisEngine(
            skip_dynamic=True, check_attestation_flag=True,
        )
        with patch.object(engine.static, "analyze_wheel", return_value=[]):
            report = engine.analyze("pkg", "1.0.0", local_wheel=whl)

        mock_check.assert_not_called()

    @patch("chaincanary.engine.check_attestation")
    @patch("chaincanary.engine.download_wheel")
    def test_attestation_skipped_when_flag_false(
        self, mock_download, mock_check, tmp_path,
    ):
        from chaincanary.engine import AnalysisEngine

        whl = tmp_path / "pkg-1.0.0-py3-none-any.whl"
        whl.write_bytes(b"PK\x03\x04")
        mock_download.return_value = whl

        engine = AnalysisEngine(
            skip_dynamic=True, check_attestation_flag=False,
        )
        with patch.object(engine.static, "analyze_wheel", return_value=[]):
            report = engine.analyze("pkg", "1.0.0")

        mock_check.assert_not_called()
        att = [f for f in report.findings if f.source == "attestation"]
        assert len(att) == 0

    @patch("chaincanary.engine.check_attestation")
    @patch("chaincanary.engine.download_wheel")
    def test_attestation_error_does_not_break_scan(
        self, mock_download, mock_check, tmp_path,
    ):
        from chaincanary.engine import AnalysisEngine

        whl = tmp_path / "pkg-1.0.0-py3-none-any.whl"
        whl.write_bytes(b"PK\x03\x04")
        mock_download.return_value = whl
        mock_check.return_value = AttestationResult(
            has_attestation=False, error="Connection error",
        )

        engine = AnalysisEngine(skip_dynamic=True)
        with patch.object(engine.static, "analyze_wheel", return_value=[]):
            report = engine.analyze("pkg", "1.0.0")

        # Error result → no attestation findings (silently skipped)
        att = [f for f in report.findings if f.source == "attestation"]
        assert len(att) == 0
        # But scan completes successfully
        assert report.verdict == "SAFE"
