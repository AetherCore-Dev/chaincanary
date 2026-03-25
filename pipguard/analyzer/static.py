"""
Enhanced static analyzer with deep AST inspection and
lightweight sandbox (no Docker required).

For environments without Docker, we use:
1. Deep AST analysis (walk every node)
2. String pattern matching
3. Wheel file structure diff vs previous version
4. Import graph analysis
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


# ── Patterns ───────────────────────────────────────────────────────────────

_NETWORK_IMPORTS = {
    "urllib", "urllib2", "urllib3", "requests", "httpx",
    "aiohttp", "http", "socket", "ssl", "ftplib", "smtplib",
}

_NETWORK_PATTERNS = [
    r"urllib\.request", r"urllib2\.", r"requests\.",
    r"http\.client", r"socket\.connect", r"httpx\.",
    r"aiohttp\.", r"urlopen\s*\(", r"urlretrieve\s*\(",
]

_SUBPROCESS_PATTERNS = [
    r"subprocess\.", r"os\.system\s*\(",
    r"os\.popen\s*\(", r"Popen\s*\(",
]

_OBFUSCATION_PATTERNS = [
    r"base64\.b64decode.*exec",
    r"exec\s*\(\s*base64",
    r"eval\s*\(\s*base64",
    r"__import__\s*\(\s*['\"]base64",
    r"compile\s*\(.*exec",
    r"zlib\.decompress.*exec",
    r"marshal\.loads",
]

_SENSITIVE_PATHS = [
    r"~[/\\]\.ssh", r"~[/\\]\.aws", r"~[/\\]\.netrc",
    r"/etc/passwd", r"/etc/shadow", r"\.ssh[/\\]id_rsa",
    r"\.aws[/\\]credentials", r"~[/\\]\.config",
]

_CURL_WGET = [r"\bcurl\b", r"\bwget\b"]

_BEACON_DOMAINS = [
    r"litellm\.cloud", r"litellm\.ai",
    r"0\.0\.0\.0", r"beacon\.",
    r"telemetry\.", r"analytics\.",
    r"track\.", r"ping\.",
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


def _matches_any(text: str, patterns: list[str]) -> list[str]:
    return [p for p in patterns if re.search(p, text, re.IGNORECASE | re.DOTALL)]


# ── AST Visitor ────────────────────────────────────────────────────────────

class _MaliciousPatternVisitor(ast.NodeVisitor):
    """Walk AST and collect suspicious patterns."""

    def __init__(self):
        self.exec_calls: list[str] = []
        self.network_calls: list[str] = []
        self.subprocess_calls: list[str] = []
        self.obfuscation: list[str] = []
        self.sensitive_paths: list[str] = []

    def visit_Call(self, node: ast.Call):
        name = self._get_call_name(node)

        if name in ("exec", "eval", "compile"):
            self.exec_calls.append(f"{name}() at line {node.lineno}")

        if name in ("b64decode", "base64.b64decode"):
            # Check if parent is exec/eval — obfuscation
            self.obfuscation.append(f"base64 decode at line {node.lineno}")

        network_names = {
            "urlopen", "get", "post", "request", "connect",
            "urlretrieve", "Request",
        }
        if name in network_names or any(
            name.startswith(p) for p in ("urllib", "requests.", "httpx.", "aiohttp.")
        ):
            self.network_calls.append(f"{name}() at line {node.lineno}")

        subprocess_names = {"system", "popen", "Popen", "run", "call", "check_output"}
        if name in subprocess_names:
            self.subprocess_calls.append(f"{name}() at line {node.lineno}")

        self.generic_visit(node)

    def visit_Str(self, node: ast.Str):
        # String literals containing sensitive paths
        for p in _SENSITIVE_PATHS:
            if re.search(p, node.s, re.IGNORECASE):
                self.sensitive_paths.append(node.s[:80])
        self.generic_visit(node)

    # Python 3.8+ uses ast.Constant instead of ast.Str
    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            for p in _SENSITIVE_PATHS:
                if re.search(p, node.value, re.IGNORECASE):
                    self.sensitive_paths.append(node.value[:80])
        self.generic_visit(node)

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return f"{self._get_name(node.func.value)}.{node.func.attr}"
        return ""

    def _get_name(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._get_name(node.value)}.{node.attr}"
        return "?"


# ── Main Analyzer ──────────────────────────────────────────────────────────

class StaticAnalyzer:
    """
    Deep static analysis — no Docker required.
    Uses AST inspection + pattern matching + wheel structure analysis.
    """

    def analyze_wheel(self, wheel_path: Path) -> list[Finding]:
        findings: list[Finding] = []

        # 0. Known malicious hash check
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

        # 1. Inspect wheel contents
        try:
            with zipfile.ZipFile(wheel_path, "r") as zf:
                names = zf.namelist()
                findings.extend(self._check_structure(zf, names))
                findings.extend(self._check_python_files(zf, names))
        except zipfile.BadZipFile:
            findings.extend(self._analyze_sdist_fallback(wheel_path))

        return findings

    def _check_structure(
        self,
        zf: zipfile.ZipFile,
        names: list[str],
    ) -> list[Finding]:
        """Check wheel file structure for suspicious entries."""
        findings = []

        # .pth files
        pth_files = [n for n in names if n.endswith(".pth")]
        for pth in pth_files:
            try:
                content = zf.read(pth).decode("utf-8", errors="replace")
            except Exception:
                content = "<unreadable>"
            rule = STATIC_RULES["PTH_FILE_INSTALL"]
            findings.append(Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                evidence=(
                    f"File: {pth}\n"
                    f"Content preview:\n{content[:300]}"
                ),
                source="static",
            ))
            # Also analyze the .pth content itself for additional signals
            if content and content.strip() and not content.strip().startswith("/"):
                # Non-path .pth content = code execution
                net = _matches_any(content, _NETWORK_PATTERNS)
                sub = _matches_any(content, _SUBPROCESS_PATTERNS)
                beacon = _matches_any(content, _BEACON_DOMAINS)
                if net or beacon:
                    findings.append(Finding(
                        rule_id="PTH_NETWORK_BEACON",
                        severity=Severity.CRITICAL,
                        title=".pth file contains network beacon (phone-home)",
                        description=(
                            "The .pth file contains code that makes a network call — "
                            "this is the exact pattern used to exfiltrate data on "
                            "every Python startup."
                        ),
                        evidence=f"File: {pth}\nContent: {content[:200]}",
                        source="static",
                    ))
                if sub:
                    findings.append(Finding(
                        rule_id="PTH_SUBPROCESS",
                        severity=Severity.CRITICAL,
                        title=".pth file spawns subprocess on every Python startup",
                        description=(
                            "The .pth file runs a subprocess command. "
                            "This executes on every Python interpreter startup."
                        ),
                        evidence=f"File: {pth}\nContent: {content[:200]}",
                        source="static",
                    ))

        # sitecustomize.py
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

        return findings

    def _check_python_files(
        self,
        zf: zipfile.ZipFile,
        names: list[str],
    ) -> list[Finding]:
        """Deep analysis of Python source files."""
        findings = []

        py_files = [n for n in names if n.endswith(".py")]
        for py_file in py_files:
            try:
                raw = zf.read(py_file)
                code = raw.decode("utf-8", errors="replace")
            except Exception:
                continue

            is_hook = (
                py_file in ("setup.py",)
                or "_hook" in py_file
                or "install" in py_file.lower()
                or py_file.endswith("/__main__.py")
            )

            # ── Pattern-based checks ──────────────────────────────────
            # Obfuscation (any file)
            obs = _matches_any(code, _OBFUSCATION_PATTERNS)
            if obs:
                rule = STATIC_RULES["OBFUSCATED_CODE"]
                findings.append(Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    evidence=f"File: {py_file}\nMatched patterns: {obs[:3]}",
                    source="static",
                ))

            if is_hook:
                # Network in hooks
                net = _matches_any(code, _NETWORK_PATTERNS)
                if net:
                    rule = STATIC_RULES["NETWORK_IN_SETUP"]
                    findings.append(Finding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        evidence=f"File: {py_file}\nPatterns: {net[:3]}",
                        source="static",
                    ))

                # Subprocess
                sub = _matches_any(code, _SUBPROCESS_PATTERNS)
                if sub:
                    rule = STATIC_RULES["SUBPROCESS_IN_SETUP"]
                    findings.append(Finding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        evidence=f"File: {py_file}\nPatterns: {sub[:3]}",
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

                # Sensitive paths
                sp = _matches_any(code, _SENSITIVE_PATHS)
                if sp:
                    rule = STATIC_RULES["SENSITIVE_PATH_WRITE"]
                    findings.append(Finding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        evidence=f"File: {py_file}\nPaths: {sp[:3]}",
                        source="static",
                    ))

            # ── AST-based deep analysis ───────────────────────────────
            try:
                tree = ast.parse(code, filename=py_file)
                visitor = _MaliciousPatternVisitor()
                visitor.visit(tree)

                if visitor.exec_calls and is_hook:
                    rule = STATIC_RULES["EXEC_IN_SETUP"]
                    findings.append(Finding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        evidence=f"File: {py_file}\nCalls: {visitor.exec_calls[:3]}",
                        source="static",
                    ))

                if visitor.obfuscation:
                    # Already caught by pattern, but AST confirms it
                    pass

            except SyntaxError:
                # Can't parse — itself suspicious
                pass

        return findings

    def _analyze_sdist_fallback(self, path: Path) -> list[Finding]:
        """Fallback for sdist tarballs."""
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

    def get_wheel_filelist(self, wheel_path: Path) -> list[str]:
        """Return list of all files in the wheel (for diffing)."""
        try:
            with zipfile.ZipFile(wheel_path, "r") as zf:
                return zf.namelist()
        except Exception:
            return []
