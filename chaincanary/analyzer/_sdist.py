"""Fallback analysis for source distributions (sdist / .tar.gz)."""

from __future__ import annotations

from chaincanary.analyzer._patterns import (
    NETWORK_PATTERNS,
    OBFUSCATION_PATTERNS,
    matches_any,
)
from chaincanary.analyzer._wheel_safety import MAX_SINGLE_FILE_BYTES
from chaincanary.analyzer.rules import STATIC_RULES
from chaincanary.models import Finding


def is_install_hook(filename: str) -> bool:
    """Determine if a Python file is an install hook."""
    basename = filename.split("/")[-1].lower()
    return (
        basename == "setup.py"
        or "_hook" in basename
        or "install" in basename
        or basename == "__main__.py"
    )


def analyze_sdist(path, package_name: str) -> list[Finding]:
    """Fallback analysis for source distributions (sdist)."""
    findings: list[Finding] = []
    try:
        import tarfile

        with tarfile.open(path, "r:gz") as tf:
            for member in tf.getmembers():
                if not member.name.endswith(".py"):
                    continue
                if member.size > MAX_SINGLE_FILE_BYTES:
                    continue
                f = tf.extractfile(member)
                if f is None:
                    continue
                code = f.read().decode("utf-8", errors="replace")

                if is_install_hook(member.name):
                    net = matches_any(code, NETWORK_PATTERNS)
                    if net:
                        rule = STATIC_RULES["NETWORK_IN_SETUP"]
                        findings.append(
                            Finding(
                                rule_id=rule.rule_id,
                                severity=rule.severity,
                                title=rule.title,
                                description=rule.description,
                                evidence=f"File: {member.name}",
                                source="static",
                            )
                        )

                obs = matches_any(code, OBFUSCATION_PATTERNS)
                if obs:
                    rule = STATIC_RULES["OBFUSCATED_CODE"]
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            title=rule.title,
                            description=rule.description,
                            evidence=f"File: {member.name}",
                            source="static",
                        )
                    )

    except Exception:
        pass
    return findings
