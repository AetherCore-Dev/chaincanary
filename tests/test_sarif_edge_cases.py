"""
Edge case tests for SARIF output generation.

Covers: boundary conditions, malformed input, unicode, special chars,
severity mismatches, control characters, and large-scale dedup.
"""

from __future__ import annotations

import json

import pytest

from chaincanary.models import Finding, RiskReport, Severity
from chaincanary.sarif import (
    _build_rules,
    _finding_to_result,
    _severity_to_level,
    _truncate_evidence,
    report_to_sarif,
    reports_to_sarif,
)

# ── Helpers ──────────────────────────────────────────────────────────


def _f(
    rule_id: str = "R",
    severity: Severity = Severity.HIGH,
    title: str = "T",
    description: str = "D",
    evidence: str = "",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        title=title,
        description=description,
        evidence=evidence,
    )


def _report(
    package: str = "pkg",
    version: str = "1.0.0",
    findings: list[Finding] | None = None,
) -> RiskReport:
    r = RiskReport(package=package, version=version)
    if findings is not None:
        r.findings = list(findings)
        r.calculate_score()
    return r


# ── 1. Empty string package name / version ────────────────────────────


class TestEmptyPackageVersion:
    def test_empty_package_name_produces_valid_sarif(self):
        sarif = report_to_sarif(_report(package="", findings=[_f()]))
        assert sarif["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"
        ]["artifactLocation"]["uri"] == "pkg:pypi/@1.0.0"

    def test_empty_version_produces_valid_sarif(self):
        sarif = report_to_sarif(_report(version="", findings=[_f()]))
        uri = sarif["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"
        ]["artifactLocation"]["uri"]
        assert uri == "pkg:pypi/pkg@"

    def test_empty_package_and_version_json_roundtrip(self):
        sarif = report_to_sarif(_report(package="", version="", findings=[_f()]))
        text = json.dumps(sarif)
        loaded = json.loads(text)
        assert len(loaded["runs"][0]["results"]) == 1

    def test_empty_strings_produce_unique_fingerprints(self):
        r1 = _finding_to_result(_f(rule_id="A"), "", "1.0")
        r2 = _finding_to_result(_f(rule_id="A"), "pkg", "1.0")
        fp_key = "primaryLocationLineHash/v1"
        assert r1["partialFingerprints"][fp_key] != r2["partialFingerprints"][fp_key]


# ── 2. None values in Finding fields ─────────────────────────────────


class TestNoneFields:
    def test_none_evidence_no_crash(self):
        f = Finding(
            rule_id="R", severity=Severity.HIGH,
            title="T", description="D", evidence=None,
        )
        result = _finding_to_result(f, "pkg", "1.0")
        assert "Evidence:" not in result["message"]["text"]

    def test_none_description_omits_full_description(self):
        f = Finding(
            rule_id="R", severity=Severity.HIGH,
            title="T", description=None,
        )
        rules = _build_rules([f])
        assert "fullDescription" not in rules[0]

    def test_empty_title_produces_rule_id_fallback(self):
        """shortDescription falls back to rule_id when title is empty."""
        f = _f(rule_id="MY_RULE", title="")
        rules = _build_rules([f])
        assert rules[0]["shortDescription"]["text"] == "MY_RULE"


# ── 3. JSON special chars in title and evidence ──────────────────────


class TestSpecialChars:
    @pytest.mark.parametrize(
        "title",
        [
            'Found: "eval" call',
            "path\\to\\file",
            "line1\nline2",
            "tab\there",
            "null\x00byte",
        ],
    )
    def test_title_with_special_chars_roundtrips(self, title):
        f = _f(title=title)
        sarif = report_to_sarif(_report(findings=[f]))
        text = json.dumps(sarif)
        loaded = json.loads(text)
        # Title appears in message text
        assert loaded["runs"][0]["results"][0]["message"]["text"]

    def test_evidence_with_null_bytes_sanitized(self):
        f = _f(evidence="before\x00after")
        result = _finding_to_result(f, "pkg", "1.0")
        assert "\x00" not in result["message"]["text"]
        assert "beforeafter" in result["message"]["text"]

    def test_evidence_with_control_chars_cleaned(self):
        # \x01 through \x08, \x0b, \x0c, \x0e-\x1f should be stripped
        evidence = "a\x01b\x02c\x0bd\x0ee"
        f = _f(evidence=evidence)
        result = _finding_to_result(f, "pkg", "1.0")
        assert "abcde" in result["message"]["text"]

    def test_evidence_preserves_tabs_and_newlines(self):
        evidence = "line1\n\tindented\rreturn"
        f = _f(evidence=evidence)
        result = _finding_to_result(f, "pkg", "1.0")
        assert "\n" in result["message"]["text"]
        assert "\t" in result["message"]["text"]


# ── 4. Special chars in rule_id ──────────────────────────────────────


class TestRuleIdSpecialChars:
    def test_rule_id_with_spaces(self):
        f = _f(rule_id="MY RULE")
        result = _finding_to_result(f, "pkg", "1.0")
        assert result["ruleId"] == "MY RULE"

    def test_rule_id_with_unicode(self):
        f = _f(rule_id="规则_001")
        result = _finding_to_result(f, "pkg", "1.0")
        assert result["ruleId"] == "规则_001"

    def test_rule_id_with_colons_in_fingerprint(self):
        """Colon in rule_id doesn't confuse fingerprint token format."""
        f1 = _f(rule_id="ns:rule")
        f2 = _f(rule_id="ns:rule")
        r1 = _finding_to_result(f1, "pkg", "1.0")
        r2 = _finding_to_result(f2, "pkg", "1.0")
        fp_key = "primaryLocationLineHash/v1"
        assert r1["partialFingerprints"][fp_key] == r2["partialFingerprints"][fp_key]

    def test_rule_id_with_slashes_json_roundtrip(self):
        f = _f(rule_id="ns/rule.v2")
        sarif = report_to_sarif(_report(findings=[f]))
        text = json.dumps(sarif)
        loaded = json.loads(text)
        assert loaded["runs"][0]["results"][0]["ruleId"] == "ns/rule.v2"


# ── 5. Evidence boundary conditions ──────────────────────────────────


class TestEvidenceBoundary:
    def test_evidence_exactly_1024_not_truncated(self):
        evidence = "x" * 1024
        result = _truncate_evidence(evidence)
        assert result == evidence
        assert "truncated" not in result

    def test_evidence_1025_is_truncated(self):
        evidence = "x" * 1025
        result = _truncate_evidence(evidence)
        assert result.endswith("… (truncated)")
        assert len(result) < 1025 + 20  # truncated output is shorter

    def test_evidence_1023_not_truncated(self):
        evidence = "x" * 1023
        result = _truncate_evidence(evidence)
        assert result == evidence

    def test_empty_evidence_not_truncated(self):
        assert _truncate_evidence("") == ""


# ── 6. Large-scale rule dedup ────────────────────────────────────────


class TestLargeScaleDedup:
    def test_1000_findings_same_rule_produces_1_rule(self):
        findings = [_f(rule_id="SAME") for _ in range(1000)]
        rules = _build_rules(findings)
        assert len(rules) == 1

    def test_1000_unique_rules_produces_1000_entries(self):
        findings = [_f(rule_id=f"RULE_{i}") for i in range(1000)]
        rules = _build_rules(findings)
        assert len(rules) == 1000

    def test_large_report_json_roundtrip(self):
        findings = [
            _f(rule_id=f"R_{i}", severity=Severity.MEDIUM)
            for i in range(500)
        ]
        sarif = report_to_sarif(_report(findings=findings))
        text = json.dumps(sarif)
        loaded = json.loads(text)
        assert len(loaded["runs"][0]["results"]) == 500
        assert len(loaded["runs"][0]["tool"]["driver"]["rules"]) == 500


# ── 7. Same rule_id, different severities ─────────────────────────────


class TestSameRuleDifferentSeverity:
    def test_results_have_different_levels(self):
        findings = [
            _f(rule_id="R", severity=Severity.CRITICAL),
            _f(rule_id="R", severity=Severity.LOW),
        ]
        sarif = report_to_sarif(_report(findings=findings))
        results = sarif["runs"][0]["results"]
        assert len(results) == 2
        assert results[0]["level"] == "error"
        assert results[1]["level"] == "note"

    def test_rules_deduplicated_to_one(self):
        findings = [
            _f(rule_id="R", severity=Severity.CRITICAL),
            _f(rule_id="R", severity=Severity.LOW),
        ]
        rules = _build_rules(findings)
        assert len(rules) == 1

    def test_rule_default_level_uses_first_seen(self):
        findings = [
            _f(rule_id="R", severity=Severity.CRITICAL),
            _f(rule_id="R", severity=Severity.LOW),
        ]
        rules = _build_rules(findings)
        assert rules[0]["defaultConfiguration"]["level"] == "error"


# ── 8. Unicode package name ──────────────────────────────────────────


class TestUnicodePackageName:
    def test_chinese_package_name_json_roundtrip(self):
        sarif = report_to_sarif(_report(package="示例包", findings=[_f()]))
        text = json.dumps(sarif, ensure_ascii=False)
        loaded = json.loads(text)
        uri = loaded["runs"][0]["results"][0]["locations"][0][
            "physicalLocation"
        ]["artifactLocation"]["uri"]
        assert "示例包" in uri

    def test_accented_package_name(self):
        sarif = report_to_sarif(_report(package="café", findings=[_f()]))
        text = json.dumps(sarif)
        loaded = json.loads(text)
        assert len(loaded["runs"][0]["results"]) == 1

    def test_unicode_fingerprint_is_stable(self):
        f = _f(rule_id="R")
        r1 = _finding_to_result(f, "示例包", "1.0")
        r2 = _finding_to_result(f, "示例包", "1.0")
        fp_key = "primaryLocationLineHash/v1"
        assert r1["partialFingerprints"][fp_key] == r2["partialFingerprints"][fp_key]


# ── 9. Non-enum severity through direct path ─────────────────────────


class TestNonEnumSeverity:
    def test_empty_string_severity(self):
        assert _severity_to_level("") == "note"

    def test_integer_severity(self):
        assert _severity_to_level(42) == "note"

    def test_none_severity(self):
        assert _severity_to_level(None) == "note"

    def test_mixed_case_severity(self):
        assert _severity_to_level("Critical") == "error"
        assert _severity_to_level("high") == "error"
        assert _severity_to_level("Medium") == "warning"


# ── 10. Malformed audit dicts ─────────────────────────────────────────


class TestMalformedAuditDicts:
    def test_entry_missing_package_key(self):
        results = [{"version": "1.0", "findings": [
            {"rule_id": "R", "severity": "HIGH", "title": "T"},
        ]}]
        sarif = reports_to_sarif(results)
        assert "unknown" in sarif["runs"][0]["results"][0][
            "locations"
        ][0]["physicalLocation"]["artifactLocation"]["uri"]

    def test_entry_missing_version_key(self):
        results = [{"package": "pkg", "findings": [
            {"rule_id": "R", "severity": "HIGH", "title": "T"},
        ]}]
        sarif = reports_to_sarif(results)
        assert len(sarif["runs"][0]["results"]) == 1

    def test_entry_missing_findings_key(self):
        results = [{"package": "pkg", "version": "1.0"}]
        sarif = reports_to_sarif(results)
        assert sarif["runs"][0]["results"] == []

    def test_findings_is_none(self):
        """findings=None should not crash."""
        results = [{"package": "pkg", "version": "1.0", "findings": None}]
        sarif = reports_to_sarif(results)
        assert sarif["runs"][0]["results"] == []

    def test_findings_is_string(self):
        """findings='accidental' should not crash."""
        results = [{"package": "pkg", "version": "1.0", "findings": "oops"}]
        sarif = reports_to_sarif(results)
        assert sarif["runs"][0]["results"] == []

    def test_entry_is_none(self):
        """None entry in list should be skipped."""
        results = [None, {"package": "pkg", "version": "1.0", "findings": [
            {"rule_id": "R", "severity": "HIGH", "title": "T"},
        ]}]
        sarif = reports_to_sarif(results)
        assert len(sarif["runs"][0]["results"]) == 1

    def test_entry_is_string(self):
        """String entry should be skipped."""
        results = ["bad", {"package": "pkg", "version": "1.0", "findings": [
            {"rule_id": "R", "severity": "HIGH", "title": "T"},
        ]}]
        sarif = reports_to_sarif(results)
        assert len(sarif["runs"][0]["results"]) == 1

    def test_finding_dict_is_string(self):
        """Non-dict finding in list should be skipped."""
        results = [{"package": "pkg", "version": "1.0", "findings": [
            "not_a_dict",
            {"rule_id": "R", "severity": "HIGH", "title": "T"},
        ]}]
        sarif = reports_to_sarif(results)
        assert len(sarif["runs"][0]["results"]) == 1

    def test_severity_none_in_finding(self):
        results = [{"package": "pkg", "version": "1.0", "findings": [
            {"rule_id": "R", "severity": None, "title": "T"},
        ]}]
        sarif = reports_to_sarif(results)
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_extra_unknown_keys_ignored(self):
        results = [{"package": "pkg", "version": "1.0", "extra": "foo", "findings": [
            {"rule_id": "R", "severity": "HIGH", "title": "T", "unknown_key": 42},
        ]}]
        sarif = reports_to_sarif(results)
        assert len(sarif["runs"][0]["results"]) == 1

    def test_empty_results_list(self):
        sarif = reports_to_sarif([])
        assert sarif["runs"][0]["results"] == []
