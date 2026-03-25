"""
PTH file content analyzer.

.pth files fall into three categories:
  1. PATH-only  — pure filesystem paths, added to sys.path
                  e.g., "/usr/local/lib/python3.11/site-packages"
  2. SAFE-CODE  — code that only references the package's own internals,
                  no external data flow (e.g., setuptools distutils shim)
  3. DANGEROUS  — code that reads sensitive data, makes network calls,
                  spawns subprocesses, or calls external endpoints

The key insight: legitimate .pth code NEVER exfiltrates data.
It may run code (setuptools does), but it only talks to itself.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class PthClass(str, Enum):
    EMPTY = "EMPTY"           # Empty or whitespace only
    PATH_ONLY = "PATH_ONLY"   # Pure filesystem paths → safe
    SAFE_CODE = "SAFE_CODE"   # Code with no external data flow → warn only
    DANGEROUS = "DANGEROUS"   # Code with external data flow → CRITICAL


@dataclass
class PthAnalysis:
    pth_class: PthClass
    risk_signals: list[str]    # what triggered the classification
    safe_signals: list[str]    # evidence it might be legitimate
    content_preview: str


# Signals that indicate DANGEROUS behavior in .pth code
_DANGEROUS_PATTERNS = [
    # Network activity
    (r"\burlopen\s*\(", "urllib network call"),
    (r"\brequests\s*\.", "requests network call"),
    (r"\bhttpx\s*\.", "httpx network call"),
    (r"\bsocket\s*\.", "raw socket"),
    (r"\bsmtplib\s*\.", "SMTP (email exfiltration?)"),
    (r"\bftplib\s*\.", "FTP connection"),
    # Subprocess / shell execution
    (r"\bsubprocess\s*\.", "subprocess spawn"),
    (r"\bos\.system\s*\(", "os.system shell"),
    (r"\bos\.popen\s*\(", "os.popen shell"),
    (r"\bPopen\s*\(", "Popen call"),
    (r"\bcurl\b", "curl invocation"),
    (r"\bwget\b", "wget invocation"),
    # Obfuscation
    (r"base64\.b64decode\s*\(.*exec", "base64+exec obfuscation"),
    (r"exec\s*\(\s*base64", "exec(base64...) obfuscation"),
    (r"zlib\.decompress\s*\(.*exec", "zlib+exec obfuscation"),
    # Credential access in .pth context (very suspicious)
    (r"\.ssh[/\\]", "SSH credential path access"),
    (r"\.aws[/\\]credentials", "AWS credentials access"),
    (r"\.netrc\b", ".netrc access"),
]

# Signals that suggest the .pth is doing something legitimate
_SAFE_INDICATORS = [
    # Only imports from its own namespace or stdlib
    (r"__import__\s*\(\s*['\"]_[a-zA-Z_]+['\"]", "imports private/internal module"),
    (r"import\s+[a-zA-Z_]+\s*;?\s*[a-zA-Z_]+\.\w+\(\)", "calls own module method"),
    # Environment variable checks without exfiltration
    (r"os\.environ\.get\s*\(", "reads env var (check for exfiltration)"),
]

# Patterns indicating the .pth file is pure path entries
_PATH_LINE_RE = re.compile(
    r"^("
    r"\s*"                          # empty line
    r"|[A-Za-z]:[/\\].*"           # Windows absolute path
    r"|/[^ \t\n\r]+"               # Unix absolute path
    r"|\.[/\\][^ \t\n\r]+"         # Relative path
    r"|\.\.?[/\\][^ \t\n\r]*"      # Parent dir path
    r")$"
)

# Import of an external (non-stdlib, non-own-package) module raises risk
_EXTERNAL_NETWORK_IMPORT_RE = re.compile(
    r"import\s+(requests|httpx|aiohttp|urllib3|pycurl|boto3|paramiko)"
)


def analyze_pth_content(content: str, package_name: str = "") -> PthAnalysis:
    """
    Classify a .pth file's content and return an analysis.
    
    package_name: used to determine if imports are "own-package" imports
    """
    stripped = content.strip()

    # 1. Empty file
    if not stripped:
        return PthAnalysis(
            pth_class=PthClass.EMPTY,
            risk_signals=[],
            safe_signals=["empty .pth file"],
            content_preview="",
        )

    lines = stripped.splitlines()

    # 2. Pure path lines
    if all(_PATH_LINE_RE.match(line.strip()) for line in lines if line.strip()):
        return PthAnalysis(
            pth_class=PthClass.PATH_ONLY,
            risk_signals=[],
            safe_signals=["all lines are filesystem paths"],
            content_preview=stripped[:200],
        )

    # 3. Code — analyze for dangerous vs safe
    risk_signals: list[str] = []
    safe_signals: list[str] = []

    for pattern, description in _DANGEROUS_PATTERNS:
        if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
            risk_signals.append(description)

    # Check for external network imports
    ext_match = _EXTERNAL_NETWORK_IMPORT_RE.search(content)
    if ext_match:
        risk_signals.append(f"imports external network library: {ext_match.group(1)}")

    # Check safe indicators
    for pattern, description in _SAFE_INDICATORS:
        if re.search(pattern, content):
            safe_signals.append(description)

    # Determine own-package references (e.g., setuptools imports _distutils_hack)
    if package_name:
        pkg_normalized = package_name.replace("-", "_").lower()
        # Check if all imports reference own package namespace
        import_refs = re.findall(r"__import__\s*\(\s*['\"]([^'\"]+)['\"]", content)
        import_refs += re.findall(r"\bimport\s+([a-zA-Z_][a-zA-Z0-9_]*)", content)
        own_imports = [r for r in import_refs if r.startswith(pkg_normalized) or r.startswith("_")]
        if own_imports and not risk_signals:
            safe_signals.append(f"only imports own-package modules: {own_imports}")

    pth_class = PthClass.DANGEROUS if risk_signals else PthClass.SAFE_CODE

    return PthAnalysis(
        pth_class=pth_class,
        risk_signals=risk_signals,
        safe_signals=safe_signals,
        content_preview=stripped[:300],
    )


def pth_severity_from_analysis(analysis: PthAnalysis) -> tuple[str, str]:
    """
    Returns (severity, explanation) based on PthAnalysis.
    
    EMPTY / PATH_ONLY → not reported at all (normal behavior)
    SAFE_CODE         → LOW  (runs code but no external data flow)
    DANGEROUS         → CRITICAL
    """
    if analysis.pth_class in (PthClass.EMPTY, PthClass.PATH_ONLY):
        return ("SAFE", "normal .pth usage")
    if analysis.pth_class == PthClass.SAFE_CODE:
        return (
            "LOW",
            "runs code on Python startup but no external data flow detected",
        )
    # DANGEROUS
    return (
        "CRITICAL",
        f"external data flow detected: {', '.join(analysis.risk_signals)}",
    )
