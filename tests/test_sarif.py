"""
Tests for SARIF v2.1.0 output generation.
"""

from __future__ import annotations

import json

import pytest

from chaincanary.models import Finding, RiskReport, Severity
from chaincanary.sarif import (
    _build_rules,
    _build_tool_driver,
    _finding_to_result,
    _severity_to_level,
    report_to_sarif,
    reports_to_sarif,
)


# ── Helpers ──────────────────────────────────────────────────────────


def _make_finding(
    rule_id: str = "TEST_RULE",
    severity: Severity = Severity.HIGH,
    title: str = "Test finding",
    description: str = "A test finding description",
    evidence: str = "",
    source: str = "static",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
        source=source,
    )


def _make_report(
    package: str = "evil-pkg",
    version: str = "1.0.0",
    findings: list[Finding] | None = None,
) -> RiskReport:
    report = RiskReport(package=package, version=version)
    if findings is not None:
        report.findings = list(findings)
        report.calculate_score()
    return report


# ── Schema compliance ────────────────────────────────────────────────


class TestSarifSchemaCompliance:
    """Verify the output matches SARIF v2.1.0 required fields."""

    def test_schema_url_is_https_with_json_suffix(self):
        sarif = report_to_sarif(_make_report())
        assert sarif["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"

    def test_version_is_2_1_0(self):
        sarif = report_to_sarif(_make_report())
        assert sarif["version"] == "2.1.0"

    def test_runs_array_present(self):
        sarif = report_to_sarif(_make_report())
        assert isinstance(sarif["runs"], list)
        assert len(sarif["runs"]) == 1

    def test_tool_driver_name(self):
        sarif = report_to_sarif(_make_report())
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "chaincanary"

    def test_tool_driver_version(self):
        sarif = report_to_sarif(_make_report())
        driver = sarif["runs"][0]["tool"]["driver"]
        assert "version" in driver
        assert "semanticVersion" in driver
        assert driver["version"] == driver["semanticVersion"]

    def test_tool_driver_information_uri(self):
        sarif = report_to_sarif(_make_report())
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["informationUri"] == (
            "https://github.com/AetherCore-Dev/chaincanary"
        )

    def test_invocations_present(self):
        sarif = report_to_sarif(_make_report())
        run = sarif["runs"][0]
        assert "invocations" in run
        assert run["invocations"][0]["executionSuccessful"] is True

    def test_results_is_list(self):
        sarif = report_to_sarif(_make_report())
        assert isinstance(sarif["runs"][0]["results"], list)

    def test_rules_is_list(self):
        sarif = report_to_sarif(_make_report())
        assert isinstance(sarif["runs"][0]["tool"]["driver"]["rules"], list)

    def test_output_is_valid_json(self):
        """Ensure the SARIF dict round-trips through JSON without errors."""
        sarif = report_to_sarif(
            _make_report(findings=[_make_finding()])
        )
        serialized = json.dumps(sarif)
        deserialized = json.loads(serialized)
        assert deserialized["version"] == "2.1.0"


# ── Empty / SAFE reports ─────────────────────────────────────────────


class TestEmptyReport:
    def test_safe_report_has_no_results(self):
        sarif = report_to_sarif(_make_report())
        assert sarif["runs"][0]["results"] == []

    def test_safe_report_has_no_rules(self):
        sarif = report_to_sarif(_make_report())
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_explicit_empty_findings_list(self):
        """findings=[] should produce same result as findings=None."""
        sarif = report_to_sarif(_make_report(findings=[]))
        assert sarif["runs"][0]["results"] == []


# ── Severity mapping ─────────────────────────────────────────────────


class TestSeverityMapping:
    @pytest.mark.parametrize(
        "severity, expected_level",
        [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFO, "note"),
        ],
    )
    def test_severity_enum_to_level(self, severity, expected_level):
        assert _severity_to_level(severity) == expected_level

    @pytest.mark.parametrize(
        "severity_str, expected_level",
        [
            ("CRITICAL", "error"),
            ("HIGH", "error"),
            ("MEDIUM", "warning"),
            ("LOW", "note"),
            ("INFO", "note"),
        ],
    )
    def test_severity_string_to_level(self, severity_str, expected_level):
        assert _severity_to_level(severity_str) == expected_level

    def test_lowercase_string_normalised_to_uppercase(self):
        """M2 fix: lowercase strings should map correctly."""
        assert _severity_to_level("critical") == "error"
        assert _severity_to_level("high") == "error"
        assert _severity_to_level("medium") == "warning"

    def test_unknown_severity_falls_back_to_note(self):
        assert _severity_to_level("UNKNOWN_LEVEL") == "note"


# ── Single finding ────────────────────────────────────────────────────


class TestSingleFinding:
    def test_result_rule_id(self):
        finding = _make_finding(
            rule_id="PTH_FILE_INSTALL", severity=Severity.CRITICAL,
        )
        result = _finding_to_result(finding, "litellm", "1.82.8")
        assert result["ruleId"] == "PTH_FILE_INSTALL"

    def test_result_level(self):
        finding = _make_finding(severity=Severity.CRITICAL)
        result = _finding_to_result(finding, "pkg", "1.0.0")
        assert result["level"] == "error"

    def test_result_message_text(self):
        finding = _make_finding(
            title="Bad thing found", description="Details here",
        )
        result = _finding_to_result(finding, "pkg", "1.0.0")
        assert "Bad thing found" in result["message"]["text"]

    def test_result_location_uses_purl(self):
        """C2 fix: artifact URI must be a valid purl."""
        finding = _make_finding()
        result = _finding_to_result(finding, "litellm", "1.82.8")
        uri = result["locations"][0]["physicalLocation"][
            "artifactLocation"
        ]["uri"]
        assert uri == "pkg:pypi/litellm@1.82.8"

    def test_result_has_partial_fingerprints_with_version_suffix(self):
        """M1 fix: fingerprint key includes /v1 suffix."""
        finding = _make_finding(rule_id="MY_RULE")
        result = _finding_to_result(finding, "pkg", "1.0.0")
        assert "partialFingerprints" in result
        assert "primaryLocationLineHash/v1" in result["partialFingerprints"]

    def test_result_evidence_in_message(self):
        finding = _make_finding(evidence="exec(base64.b64decode('...'))")
        result = _finding_to_result(finding, "pkg", "1.0.0")
        assert "exec(base64.b64decode" in result["message"]["text"]

    def test_message_without_evidence_has_no_evidence_section(self):
        finding = _make_finding(evidence="")
        result = _finding_to_result(finding, "pkg", "1.0.0")
        assert "Evidence:" not in result["message"]["text"]

    def test_message_with_evidence_has_single_separator(self):
        """H1 fix: no triple newline before Evidence."""
        finding = _make_finding(
            title="Title", evidence="proof",
        )
        result = _finding_to_result(finding, "pkg", "1.0.0")
        text = result["message"]["text"]
        assert "Title\n\nEvidence:\nproof" == text

    def test_long_evidence_is_truncated(self):
        """L3 fix: evidence capped at 1024 chars."""
        long_evidence = "x" * 2000
        finding = _make_finding(evidence=long_evidence)
        result = _finding_to_result(finding, "pkg", "1.0.0")
        assert "… (truncated)" in result["message"]["text"]
        # Total message should be much shorter than 2000 chars of evidence
        assert len(result["message"]["text"]) < 1200


# ── Partial fingerprints stability ────────────────────────────────────


class TestPartialFingerprints:
    _FP_KEY = "primaryLocationLineHash/v1"

    def test_same_input_produces_same_fingerprint(self):
        f1 = _make_finding(rule_id="RULE_A")
        f2 = _make_finding(rule_id="RULE_A")
        r1 = _finding_to_result(f1, "pkg", "1.0.0")
        r2 = _finding_to_result(f2, "pkg", "1.0.0")
        assert (
            r1["partialFingerprints"][self._FP_KEY]
            == r2["partialFingerprints"][self._FP_KEY]
        )

    def test_different_rule_produces_different_fingerprint(self):
        f1 = _make_finding(rule_id="RULE_A")
        f2 = _make_finding(rule_id="RULE_B")
        r1 = _finding_to_result(f1, "pkg", "1.0.0")
        r2 = _finding_to_result(f2, "pkg", "1.0.0")
        assert (
            r1["partialFingerprints"][self._FP_KEY]
            != r2["partialFingerprints"][self._FP_KEY]
        )

    def test_different_package_produces_different_fingerprint(self):
        f = _make_finding(rule_id="RULE_A")
        r1 = _finding_to_result(f, "pkg-a", "1.0.0")
        r2 = _finding_to_result(f, "pkg-b", "1.0.0")
        assert (
            r1["partialFingerprints"][self._FP_KEY]
            != r2["partialFingerprints"][self._FP_KEY]
        )

    def test_fingerprint_is_hex_sha256(self):
        f = _make_finding()
        r = _finding_to_result(f, "pkg", "1.0.0")
        fp = r["partialFingerprints"][self._FP_KEY]
        # SHA256 hex digest is 64 chars
        assert len(fp) == 64
        int(fp, 16)  # should not raise


# ── Multiple findings → deduplicated rules ────────────────────────────


class TestMultipleFindings:
    def test_multiple_findings_in_results(self):
        findings = [
            _make_finding(rule_id="RULE_A", severity=Severity.CRITICAL),
            _make_finding(rule_id="RULE_B", severity=Severity.HIGH),
            _make_finding(rule_id="RULE_C", severity=Severity.MEDIUM),
        ]
        sarif = report_to_sarif(_make_report(findings=findings))
        assert len(sarif["runs"][0]["results"]) == 3

    def test_rules_are_deduplicated(self):
        findings = [
            _make_finding(
                rule_id="SAME_RULE", severity=Severity.HIGH, title="First",
            ),
            _make_finding(
                rule_id="SAME_RULE", severity=Severity.HIGH, title="Second",
            ),
        ]
        sarif = report_to_sarif(_make_report(findings=findings))
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "SAME_RULE"

    def test_each_unique_rule_id_in_rules(self):
        findings = [
            _make_finding(rule_id="A"),
            _make_finding(rule_id="B"),
            _make_finding(rule_id="C"),
        ]
        rules = _build_rules(findings)
        rule_ids = {r["id"] for r in rules}
        assert rule_ids == {"A", "B", "C"}

    def test_rule_has_short_description(self):
        findings = [_make_finding(rule_id="X", title="My title")]
        rules = _build_rules(findings)
        assert rules[0]["shortDescription"]["text"] == "My title"

    def test_rule_has_full_description_when_nonempty(self):
        findings = [_make_finding(rule_id="X", description="Full desc")]
        rules = _build_rules(findings)
        assert rules[0]["fullDescription"]["text"] == "Full desc"

    def test_rule_omits_full_description_when_empty(self):
        """H5 fix: empty fullDescription violates SARIF spec."""
        findings = [_make_finding(rule_id="X", description="")]
        rules = _build_rules(findings)
        assert "fullDescription" not in rules[0]

    def test_rule_has_default_configuration_level(self):
        findings = [_make_finding(severity=Severity.CRITICAL)]
        rules = _build_rules(findings)
        assert rules[0]["defaultConfiguration"]["level"] == "error"


# ── Rules from registry (rules.py) ───────────────────────────────────


class TestRulesFromRegistry:
    """When a finding's rule_id matches a rule in rules.py, use its desc."""

    def test_known_rule_uses_registry_description(self):
        finding = _make_finding(
            rule_id="PTH_FILE_INSTALL",
            severity=Severity.CRITICAL,
            title="override title",
            description="override desc",
        )
        rules = _build_rules([finding])
        from chaincanary.analyzer.rules import ALL_RULES

        expected = ALL_RULES["PTH_FILE_INSTALL"].description
        assert rules[0]["fullDescription"]["text"] == expected

    def test_unknown_rule_uses_finding_description(self):
        finding = _make_finding(
            rule_id="CUSTOM_THING",
            description="My custom description",
        )
        rules = _build_rules([finding])
        assert rules[0]["fullDescription"]["text"] == "My custom description"

    def test_known_rule_uses_registry_title(self):
        finding = _make_finding(rule_id="OBFUSCATED_CODE", title="whatever")
        rules = _build_rules([finding])
        from chaincanary.analyzer.rules import ALL_RULES

        expected = ALL_RULES["OBFUSCATED_CODE"].title
        assert rules[0]["shortDescription"]["text"] == expected


# ── Audit batch (reports_to_sarif) ────────────────────────────────────


class TestAuditSarif:
    def test_multiple_packages_in_single_run(self):
        results = [
            {
                "package": "pkg-a",
                "version": "1.0.0",
                "score": 8.0,
                "verdict": "MALICIOUS",
                "findings": [
                    {
                        "rule_id": "RULE_1",
                        "severity": "CRITICAL",
                        "title": "Bad",
                        "description": "Very bad",
                    },
                ],
            },
            {
                "package": "pkg-b",
                "version": "2.0.0",
                "score": 0.0,
                "verdict": "SAFE",
                "findings": [],
            },
        ]
        sarif = reports_to_sarif(results)
        assert len(sarif["runs"]) == 1
        # only pkg-a has findings
        assert len(sarif["runs"][0]["results"]) == 1

    def test_audit_sarif_schema(self):
        sarif = reports_to_sarif([])
        assert sarif["$schema"] == (
            "https://json.schemastore.org/sarif-2.1.0.json"
        )
        assert sarif["version"] == "2.1.0"

    def test_audit_empty_results(self):
        sarif = reports_to_sarif([])
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_audit_invocations_present(self):
        """M8 fix: invocations must also be in audit SARIF."""
        sarif = reports_to_sarif([])
        inv = sarif["runs"][0]["invocations"]
        assert len(inv) == 1
        assert inv[0]["executionSuccessful"] is True

    def test_audit_deduplicates_rules_across_packages(self):
        results = [
            {
                "package": "pkg-a",
                "version": "1.0.0",
                "score": 4.0,
                "verdict": "HIGH_RISK",
                "findings": [
                    {
                        "rule_id": "SHARED_RULE",
                        "severity": "HIGH",
                        "title": "X",
                        "description": "D",
                    },
                ],
            },
            {
                "package": "pkg-b",
                "version": "2.0.0",
                "score": 4.0,
                "verdict": "HIGH_RISK",
                "findings": [
                    {
                        "rule_id": "SHARED_RULE",
                        "severity": "HIGH",
                        "title": "X",
                        "description": "D",
                    },
                ],
            },
        ]
        sarif = reports_to_sarif(results)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1

    def test_audit_results_use_purl_in_location(self):
        results = [
            {
                "package": "evil",
                "version": "0.1",
                "score": 8.0,
                "verdict": "MALICIOUS",
                "findings": [
                    {
                        "rule_id": "R",
                        "severity": "CRITICAL",
                        "title": "T",
                        "description": "D",
                    },
                ],
            },
        ]
        sarif = reports_to_sarif(results)
        loc = sarif["runs"][0]["results"][0]["locations"][0]
        uri = loc["physicalLocation"]["artifactLocation"]["uri"]
        assert uri == "pkg:pypi/evil@0.1"

    def test_audit_findings_without_description_key(self):
        """Audit results from CLI may not have 'description' — handle ok."""
        results = [
            {
                "package": "pkg",
                "version": "1.0",
                "score": 2.5,
                "verdict": "LOW_RISK",
                "findings": [
                    {"rule_id": "R", "severity": "HIGH", "title": "Title only"},
                ],
            },
        ]
        sarif = reports_to_sarif(results)
        assert len(sarif["runs"][0]["results"]) == 1

    def test_audit_invalid_severity_falls_back_to_info(self):
        """M6 fix: unknown severity string → Severity.INFO."""
        results = [
            {
                "package": "pkg",
                "version": "1.0",
                "score": 0,
                "verdict": "SAFE",
                "findings": [
                    {
                        "rule_id": "R",
                        "severity": "SUPER_CRITICAL",
                        "title": "T",
                    },
                ],
            },
        ]
        sarif = reports_to_sarif(results)
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_audit_json_roundtrip(self):
        """L5 fix: audit SARIF must be JSON-serializable."""
        results = [
            {
                "package": "pkg",
                "version": "1.0",
                "score": 4.0,
                "verdict": "HIGH_RISK",
                "findings": [
                    {
                        "rule_id": "R",
                        "severity": "HIGH",
                        "title": "T",
                        "description": "D",
                    },
                ],
            },
        ]
        sarif = reports_to_sarif(results)
        text = json.dumps(sarif)
        loaded = json.loads(text)
        assert loaded["version"] == "2.1.0"


# ── Tool driver builder ───────────────────────────────────────────────


class TestToolDriver:
    def test_driver_has_required_fields(self):
        driver = _build_tool_driver([])
        assert "name" in driver
        assert "version" in driver
        assert "informationUri" in driver
        assert "rules" in driver

    def test_driver_name_is_chaincanary(self):
        driver = _build_tool_driver([])
        assert driver["name"] == "chaincanary"

    def test_driver_rules_from_arg(self):
        rules = [{"id": "X", "shortDescription": {"text": "X"}}]
        driver = _build_tool_driver(rules)
        assert driver["rules"] == rules


# ── Integration: full report → SARIF → JSON round-trip ────────────────


class TestFullRoundTrip:
    def test_malicious_report_roundtrip(self):
        findings = [
            _make_finding(
                rule_id="PTH_FILE_INSTALL",
                severity=Severity.CRITICAL,
                title=".pth file installed",
                description="Dangerous .pth",
                evidence="import subprocess; subprocess.Popen(...)",
            ),
            _make_finding(
                rule_id="OBFUSCATED_CODE",
                severity=Severity.HIGH,
                title="base64 + exec",
                description="Obfuscated payload",
            ),
            _make_finding(
                rule_id="KNOWN_MALICIOUS_HASH",
                severity=Severity.CRITICAL,
                title="Known malware hash",
                description="SHA256 match",
            ),
        ]
        report = _make_report(
            package="litellm", version="1.82.8", findings=findings,
        )
        sarif = report_to_sarif(report)

        # Round-trip through JSON
        text = json.dumps(sarif, indent=2)
        loaded = json.loads(text)

        # Verify structure
        run = loaded["runs"][0]
        assert len(run["results"]) == 3
        assert len(run["tool"]["driver"]["rules"]) == 3

        # Verify all results have required fields
        for result in run["results"]:
            assert "ruleId" in result
            assert "level" in result
            assert "message" in result
            assert "text" in result["message"]
            assert "locations" in result
            assert "partialFingerprints" in result

    def test_low_risk_report_roundtrip(self):
        findings = [
            _make_finding(
                rule_id="TYPOSQUATTING",
                severity=Severity.MEDIUM,
                title="Typo",
            ),
        ]
        report = _make_report(
            package="reqeusts", version="1.0.0", findings=findings,
        )
        sarif = report_to_sarif(report)
        text = json.dumps(sarif)
        loaded = json.loads(text)
        assert loaded["runs"][0]["results"][0]["level"] == "warning"

    def test_info_finding_roundtrip(self):
        findings = [
            _make_finding(
                rule_id="DOWNLOAD_FAILED",
                severity=Severity.INFO,
                title="Download failed",
            ),
        ]
        report = _make_report(findings=findings)
        sarif = report_to_sarif(report)
        assert sarif["runs"][0]["results"][0]["level"] == "note"
