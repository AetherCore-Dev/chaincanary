"""
Detection rules for pipguard.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable
from pipguard.models import Severity


@dataclass
class Rule:
    rule_id: str
    severity: Severity
    title: str
    description: str
    source: str = "static"  # "static" | "dynamic" | "both"


# ─────────────────────────────────────────────
# Static Rules
# ─────────────────────────────────────────────
STATIC_RULES = {
    "PTH_FILE_INSTALL": Rule(
        rule_id="PTH_FILE_INSTALL",
        severity=Severity.CRITICAL,
        title=".pth file installed — executes on every Python startup",
        description=(
            "The package installs a .pth file. Python automatically executes "
            "any .pth file containing non-path lines on every interpreter startup. "
            "This is the exact mechanism used in the LiteLLM 1.82.7 attack (2026-03-24)."
        ),
        source="static",
    ),
    "EXEC_IN_SETUP": Rule(
        rule_id="EXEC_IN_SETUP",
        severity=Severity.HIGH,
        title="exec() or eval() called in setup.py / install hooks",
        description="Dynamic code execution during package installation is a major red flag.",
        source="static",
    ),
    "OBFUSCATED_CODE": Rule(
        rule_id="OBFUSCATED_CODE",
        severity=Severity.HIGH,
        title="Obfuscated code detected (base64 + exec pattern)",
        description="Code is hidden via base64 encoding before execution — common malware technique.",
        source="static",
    ),
    "NETWORK_IN_SETUP": Rule(
        rule_id="NETWORK_IN_SETUP",
        severity=Severity.HIGH,
        title="Network request in setup.py or install hooks",
        description="Package makes network calls during installation — could be C2 beacon or data exfiltration.",
        source="static",
    ),
    "SUBPROCESS_IN_SETUP": Rule(
        rule_id="SUBPROCESS_IN_SETUP",
        severity=Severity.MEDIUM,
        title="Subprocess spawned during install",
        description="Package spawns child processes during installation.",
        source="static",
    ),
    "SENSITIVE_PATH_WRITE": Rule(
        rule_id="SENSITIVE_PATH_WRITE",
        severity=Severity.HIGH,
        title="Writes to sensitive path detected",
        description="Package writes files to sensitive locations (~/.ssh, ~/.aws, /etc, etc.).",
        source="static",
    ),
    "KNOWN_MALICIOUS_HASH": Rule(
        rule_id="KNOWN_MALICIOUS_HASH",
        severity=Severity.CRITICAL,
        title="Known malicious package hash detected",
        description="This package matches a known malicious artifact in the pipguard threat database.",
        source="static",
    ),
    "SITECUSTOMIZE_MODIFY": Rule(
        rule_id="SITECUSTOMIZE_MODIFY",
        severity=Severity.CRITICAL,
        title="Modifies sitecustomize.py — executes on every Python startup",
        description=(
            "sitecustomize.py is executed automatically by Python on startup. "
            "Modifying this file achieves similar persistence to .pth injection."
        ),
        source="static",
    ),
    "CURL_WGET_IN_SETUP": Rule(
        rule_id="CURL_WGET_IN_SETUP",
        severity=Severity.HIGH,
        title="curl/wget command in setup.py",
        description="Package downloads external content via shell commands during installation.",
        source="static",
    ),
}

# ─────────────────────────────────────────────
# Dynamic Rules (sandbox-based)
# ─────────────────────────────────────────────
DYNAMIC_RULES = {
    "OUTBOUND_NETWORK": Rule(
        rule_id="OUTBOUND_NETWORK",
        severity=Severity.HIGH,
        title="Outbound network connection during install",
        description="Package made a real network connection during installation in the sandbox.",
        source="dynamic",
    ),
    "FILE_WRITE_HOMEDIR": Rule(
        rule_id="FILE_WRITE_HOMEDIR",
        severity=Severity.HIGH,
        title="File written outside package directory",
        description="Package wrote files to locations outside its own install directory.",
        source="dynamic",
    ),
    "ENV_VAR_EXFIL": Rule(
        rule_id="ENV_VAR_EXFIL",
        severity=Severity.CRITICAL,
        title="Environment variable read + network call (credential exfiltration?)",
        description=(
            "Package read environment variables (possibly containing API keys/secrets) "
            "AND made a network call — high probability of credential exfiltration."
        ),
        source="dynamic",
    ),
    "PERSISTENT_HOOK": Rule(
        rule_id="PERSISTENT_HOOK",
        severity=Severity.CRITICAL,
        title="Persistence hook installed (.pth / sitecustomize confirmed in sandbox)",
        description="Dynamic analysis confirmed the package installs a persistence hook.",
        source="dynamic",
    ),
    "SUBPROCESS_SPAWN": Rule(
        rule_id="SUBPROCESS_SPAWN",
        severity=Severity.MEDIUM,
        title="Subprocess spawned during install (confirmed in sandbox)",
        description="Package spawned child processes — confirmed by sandbox monitoring.",
        source="dynamic",
    ),
    "CREDENTIAL_FILE_READ": Rule(
        rule_id="CREDENTIAL_FILE_READ",
        severity=Severity.CRITICAL,
        title="Credential file accessed (~/.aws, ~/.ssh, ~/.netrc)",
        description="Package attempted to read credential files during installation.",
        source="dynamic",
    ),
}

ALL_RULES = {**STATIC_RULES, **DYNAMIC_RULES}
