"""
SARIF v2.1.0 output generation for chaincanary.

Converts RiskReport (single check) or audit result dicts (batch)
into SARIF JSON that GitHub Code Scanning accepts.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import hashlib
from typing import Any

from chaincanary import __version__
from chaincanary.models import Finding, RiskReport, Severity

_SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "chaincanary"
_INFO_URI = "https://github.com/AetherCore-Dev/chaincanary"

# Max evidence length to prevent SARIF from exceeding GitHub's 10 MB limit
_MAX_EVIDENCE_LEN = 1024

# Severity → SARIF level
_LEVEL_MAP: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def _severity_to_level(severity: Severity | str) -> str:
    """Map a chaincanary severity to a SARIF result level."""
    key = severity.value if isinstance(severity, Severity) else str(severity).upper()
    return _LEVEL_MAP.get(key, "note")


def _fingerprint(package: str, version: str, rule_id: str) -> str:
    """Stable SHA-256 fingerprint for GitHub deduplication."""
    token = f"{package}=={version}:{rule_id}"
    return hashlib.sha256(token.encode()).hexdigest()


def _package_to_purl(package: str, version: str) -> str:
    """Convert package name + version to a Package URL (purl) spec."""
    return f"pkg:pypi/{package}@{version}"


def _sanitize_evidence(text: str) -> str:
    """Remove null bytes and non-printable control chars from evidence."""
    # Keep \t (9), \n (10), \r (13); strip all other C0 control chars
    return text.translate(
        {i: None for i in range(0, 0x20) if i not in (9, 10, 13)}
    )


def _truncate_evidence(evidence: str) -> str:
    """Truncate evidence to prevent SARIF bloat."""
    sanitized = _sanitize_evidence(evidence)
    if len(sanitized) <= _MAX_EVIDENCE_LEN:
        return sanitized
    return sanitized[:_MAX_EVIDENCE_LEN] + "\n… (truncated)"


def _finding_to_result(
    finding: Finding, package: str, version: str,
) -> dict[str, Any]:
    """Convert a single Finding into a SARIF result object."""
    message_text = finding.title
    if finding.evidence:
        truncated = _truncate_evidence(finding.evidence)
        message_text = f"{finding.title}\n\nEvidence:\n{truncated}"

    return {
        "ruleId": finding.rule_id,
        "level": _severity_to_level(finding.severity),
        "message": {"text": message_text},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": _package_to_purl(package, version),
                    },
                }
            }
        ],
        "partialFingerprints": {
            "primaryLocationLineHash/v1": _fingerprint(
                package, version, finding.rule_id,
            ),
        },
    }


def _build_rules(findings: list[Finding]) -> list[dict[str, Any]]:
    """
    Build a deduplicated SARIF rules array from a list of findings.

    If the rule_id exists in the chaincanary rule registry (rules.py),
    the registry's title and description are used instead of the finding's.
    """
    from chaincanary.analyzer.rules import ALL_RULES

    seen: dict[str, dict[str, Any]] = {}

    for f in findings:
        if f.rule_id in seen:
            continue

        registry_rule = ALL_RULES.get(f.rule_id)
        title = registry_rule.title if registry_rule else f.title
        description = (
            registry_rule.description if registry_rule else f.description
        )
        severity = registry_rule.severity if registry_rule else f.severity

        rule: dict[str, Any] = {
            "id": f.rule_id,
            "shortDescription": {"text": title or f.rule_id},
            "defaultConfiguration": {
                "level": _severity_to_level(severity),
            },
        }
        # Only include fullDescription when non-empty (SARIF spec §3.49.2)
        if description:
            rule["fullDescription"] = {"text": description}

        seen[f.rule_id] = rule

    return list(seen.values())


def _build_tool_driver(rules: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the tool.driver object with chaincanary metadata."""
    return {
        "name": _TOOL_NAME,
        "version": __version__,
        "semanticVersion": __version__,
        "informationUri": _INFO_URI,
        "rules": rules,
    }


def report_to_sarif(report: RiskReport) -> dict[str, Any]:
    """
    Convert a single RiskReport into a complete SARIF v2.1.0 document.

    Used by the `check` command.
    """
    results = [
        _finding_to_result(f, report.package, report.version)
        for f in report.findings
    ]
    rules = _build_rules(report.findings)

    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": _build_tool_driver(rules)},
                "results": results,
                "invocations": [{"executionSuccessful": True}],
            }
        ],
    }


def reports_to_sarif(
    audit_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Convert a list of audit result dicts into a single SARIF document.

    Used by the `audit` command. Each audit result dict has keys:
    package, version, score, verdict, findings (list of dicts).
    All results go into a single SARIF run.
    """
    all_findings: list[Finding] = []
    sarif_results: list[dict[str, Any]] = []

    for entry in audit_results:
        if not isinstance(entry, dict):
            continue

        package = entry.get("package", "unknown")
        version = entry.get("version", "unknown")

        findings_raw = entry.get("findings")
        if not isinstance(findings_raw, list):
            continue

        for f_dict in findings_raw:
            if not isinstance(f_dict, dict):
                continue

            severity_str = f_dict.get("severity", "INFO")
            try:
                severity = Severity(severity_str)
            except (ValueError, KeyError):
                severity = Severity.INFO

            finding = Finding(
                rule_id=f_dict.get("rule_id", "UNKNOWN"),
                severity=severity,
                title=f_dict.get("title", ""),
                description=f_dict.get("description", ""),
                source=f_dict.get("source", "static"),
            )
            all_findings.append(finding)
            sarif_results.append(
                _finding_to_result(finding, package, version),
            )

    rules = _build_rules(all_findings)

    return {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {"driver": _build_tool_driver(rules)},
                "results": sarif_results,
                "invocations": [{"executionSuccessful": True}],
            }
        ],
    }
