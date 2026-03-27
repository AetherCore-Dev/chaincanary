"""
Static analyzer — deep, no sandbox required.

Design principles:
  1. Zero false negatives on known attack patterns (LiteLLM 1.82.7)
  2. Minimize false positives — understand *intent*, not just presence of patterns
  3. Defense against malicious wheels (zip bombs, path traversal)
  4. Layered: structural checks → .pth semantic analysis → AST deep scan
"""

from __future__ import annotations

import zipfile
from pathlib import Path

from chaincanary.analyzer._file_checks import (
    check_python_files,
    check_structure,
)
from chaincanary.analyzer._hash_check import (
    MALICIOUS_HASHES,
    lookup_hash_metadata,
    sha256_file,
)
from chaincanary.analyzer._sdist import analyze_sdist
from chaincanary.analyzer._wheel_safety import (
    WheelSecurityError,
    validate_wheel_safety,
)
from chaincanary.analyzer.rules import STATIC_RULES
from chaincanary.models import Finding

# Re-export for backward compatibility
__all__ = ["StaticAnalyzer", "WheelSecurityError"]


class StaticAnalyzer:
    """
    Deep static analysis — no Docker required.

    Analysis layers:
      1. Wheel integrity (zip safety)
      2. Known malicious hash
      3. File structure (.pth, sitecustomize)  ← semantic .pth analysis
      4. Install hook analysis (setup.py)
      5. Deep scan of all Python files (delayed-trigger detection)
    """

    def analyze_wheel(self, wheel_path: Path, package_name: str = "") -> list[Finding]:
        findings: list[Finding] = []

        # Infer package name from wheel filename if not provided
        if not package_name:
            package_name = wheel_path.stem.split("-")[0].lower()

        # ── 1. Known malicious hash ────────────────────────────────
        file_hash = sha256_file(wheel_path)
        if file_hash in MALICIOUS_HASHES:
            rule = STATIC_RULES["KNOWN_MALICIOUS_HASH"]
            metadata = lookup_hash_metadata(file_hash)
            evidence = f"SHA256: {file_hash}"
            if metadata:
                evidence += (
                    f"\nPackage: {metadata.get('package', '?')}"
                    f"=={metadata.get('version', '?')}"
                    f"\nAttack: {metadata.get('attack_type', 'unknown')}"
                    f"\nSource: {metadata.get('source', 'unknown')}"
                )
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    evidence=evidence,
                    source="static",
                )
            )

        # ── 2. Open and validate zip ───────────────────────────────
        try:
            with zipfile.ZipFile(wheel_path, "r") as zf:
                safety_finding = validate_wheel_safety(zf)
                if safety_finding:
                    findings.append(safety_finding)
                    if safety_finding.rule_id == "WHEEL_ZIP_BOMB":
                        return findings  # Don't process further

                names = zf.namelist()
                findings.extend(check_structure(zf, names, package_name))
                findings.extend(check_python_files(zf, names, package_name))

        except zipfile.BadZipFile:
            findings.extend(analyze_sdist(wheel_path, package_name))

        return findings

    def get_wheel_filelist(self, wheel_path: Path) -> list[str]:
        try:
            with zipfile.ZipFile(wheel_path, "r") as zf:
                return zf.namelist()
        except Exception:
            return []
