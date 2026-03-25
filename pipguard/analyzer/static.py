"""
Static analyzer — fast, no sandbox required.
Unpacks the wheel/sdist and inspects files without executing anything.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import zipfile
from pathlib import Path
from typing import Optional

from pipguard.models import Finding, Severity
from pipguard.analyzer.rules import STATIC_RULES


# ── Patterns we look for in source code ────────────────────────────────────
_NETWORK_PATTERNS = [
    r"urllib\.request",
    r"urllib2\.",
    r"requests\.",
    r"http\.client",
    r"socket\.connect",
    r"httplib\.",
    r"aiohttp\.",
    r"httpx\.",
]

_SUBPROCESS_PATTERNS = [
    r"subprocess\.",
    r"os\.system\s*\(",
    r"os\.popen\s*\(",
    r"popen\s*\(",
]

_OBFUSCATION_PATTERNS = [
    r"base64\.b64decode.*exec",
    r"exec\s*\(\s*base64",
    r"eval\s*\(\s*base64",
    r"__import__\s*\(\s*['\"]base64",
    r"compile\s*\(.*exec",
]

_SENSITIVE_PATHS = [
    r"~/\.ssh",
    r"~/\.aws",
    r"~/\.netrc",
    r"/etc/passwd",
    r"/etc/shadow",
    r"\.ssh/id_rsa",
    r"\.aws/credentials",
]

_CURL_WGET = [
    r"\bcurl\b",
    r"\bwget\b",
]


def _load_malicious_hashes() -> set[str]:
    db_path = Path(__file__).parent.parent / "db" / "known_malicious.json"
    if not db_path.exists():
        return set()
    with open(db_path) as f:
        data = json.load(f)
    return set(data.get("sha256", []))


_MALICIOUS_HASHES: set[str] = _load_malicious_hashes()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _matches_any(text: str, patterns: list[str]) -> list[str]:
    matched = []
    for p in patterns:
        if re.search(p, text, re.IGNORECASE):
            matched.append(p)
    return matched


class StaticAnalyzer:
    """
    Analyze a wheel or sdist without executing any code.
    """

    def analyze_wheel(self, wheel_path: Path) -> list[Finding]:
        """
        Main entry point. Returns list of Findings.
        """
        findings: list[Finding] = []

        # 0. Check hash against known malicious database
        file_hash = _sha256_file(wheel_path)
        if file_hash in _MALICIOUS_HASHES:
            rule = STATIC_RULES["KNOWN_MALICIOUS_HASH"]
            findings.append(Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                evidence=f"SHA256: {file_hash}",
                source="static",
            ))
            # If we know it's malicious, still continue for full picture

        # 1. Extract and inspect contents
        try:
            with zipfile.ZipFile(wheel_path, "r") as zf:
                names = zf.namelist()

                # Check for .pth files
                pth_files = [n for n in names if n.endswith(".pth")]
                for pth in pth_files:
                    content = zf.read(pth).decode("utf-8", errors="replace")
                    rule = STATIC_RULES["PTH_FILE_INSTALL"]
                    findings.append(Finding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        evidence=f"File: {pth}\nContent: {content[:200]}",
                        source="static",
                    ))

                # Check for sitecustomize.py
                site_files = [n for n in names if "sitecustomize" in n.lower()]
                for sf in site_files:
                    rule = STATIC_RULES["SITECUSTOMIZE_MODIFY"]
                    findings.append(Finding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        evidence=f"File: {sf}",
                        source="static",
                    ))

                # Inspect Python source files
                py_files = [n for n in names if n.endswith(".py")]
                for py_file in py_files:
                    try:
                        code = zf.read(py_file).decode("utf-8", errors="replace")
                    except Exception:
                        continue

                    is_setup = py_file in ("setup.py", "setup.cfg") or "install" in py_file.lower()

                    # Check for obfuscation patterns (any file)
                    obs = _matches_any(code, _OBFUSCATION_PATTERNS)
                    if obs:
                        rule = STATIC_RULES["OBFUSCATED_CODE"]
                        findings.append(Finding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            title=rule.title,
                            description=rule.description,
                            evidence=f"File: {py_file}\nPatterns: {obs}",
                            source="static",
                        ))

                    if is_setup or "_hook" in py_file or "install" in py_file.lower():
                        # Network in install hooks
                        net = _matches_any(code, _NETWORK_PATTERNS)
                        if net:
                            rule = STATIC_RULES["NETWORK_IN_SETUP"]
                            findings.append(Finding(
                                rule_id=rule.rule_id,
                                severity=rule.severity,
                                title=rule.title,
                                description=rule.description,
                                evidence=f"File: {py_file}\nPatterns: {net}",
                                source="static",
                            ))

                        # Subprocess in install hooks
                        sub = _matches_any(code, _SUBPROCESS_PATTERNS)
                        if sub:
                            rule = STATIC_RULES["SUBPROCESS_IN_SETUP"]
                            findings.append(Finding(
                                rule_id=rule.rule_id,
                                severity=rule.severity,
                                title=rule.title,
                                description=rule.description,
                                evidence=f"File: {py_file}\nPatterns: {sub}",
                                source="static",
                            ))

                        # curl/wget
                        cw = _matches_any(code, _CURL_WGET)
                        if cw:
                            rule = STATIC_RULES["CURL_WGET_IN_SETUP"]
                            findings.append(Finding(
                                rule_id=rule.rule_id,
                                severity=rule.severity,
                                title=rule.title,
                                description=rule.description,
                                evidence=f"File: {py_file}\nPatterns: {cw}",
                                source="static",
                            ))

                        # Sensitive path writes
                        sp = _matches_any(code, _SENSITIVE_PATHS)
                        if sp:
                            rule = STATIC_RULES["SENSITIVE_PATH_WRITE"]
                            findings.append(Finding(
                                rule_id=rule.rule_id,
                                severity=rule.severity,
                                title=rule.title,
                                description=rule.description,
                                evidence=f"File: {py_file}\nPaths: {sp}",
                                source="static",
                            ))

                        # exec / eval in setup
                        if re.search(r"\bexec\s*\(", code) or re.search(r"\beval\s*\(", code):
                            rule = STATIC_RULES["EXEC_IN_SETUP"]
                            findings.append(Finding(
                                rule_id=rule.rule_id,
                                severity=rule.severity,
                                title=rule.title,
                                description=rule.description,
                                evidence=f"File: {py_file}",
                                source="static",
                            ))

        except zipfile.BadZipFile:
            # Could be an sdist (.tar.gz) — basic text scan
            findings.extend(self._analyze_sdist(wheel_path))

        return findings

    def _analyze_sdist(self, path: Path) -> list[Finding]:
        """Fallback for sdist tarballs — basic text scan."""
        findings = []
        try:
            import tarfile
            with tarfile.open(path, "r:gz") as tf:
                for member in tf.getmembers():
                    if not member.name.endswith(".py"):
                        continue
                    f = tf.extractfile(member)
                    if f is None:
                        continue
                    code = f.read().decode("utf-8", errors="replace")
                    if re.search(r"\bexec\s*\(", code):
                        rule = STATIC_RULES["EXEC_IN_SETUP"]
                        findings.append(Finding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            title=rule.title,
                            description=rule.description,
                            evidence=f"File: {member.name}",
                            source="static",
                        ))
        except Exception:
            pass
        return findings
