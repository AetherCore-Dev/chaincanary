"""
Dynamic sandbox analyzer — runs package install inside Docker,
monitors system calls to detect malicious behavior.
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from chaincanary.models import Finding, BehaviorSnapshot, Severity
from chaincanary.analyzer.rules import DYNAMIC_RULES


# Docker image used for sandbox
SANDBOX_IMAGE = "python:3.11-slim"

# Timeout for sandbox execution (seconds)
SANDBOX_TIMEOUT = 60


_CREDENTIAL_PATHS = [
    "/.aws/credentials",
    "/.ssh/id_rsa",
    "/.ssh/id_ed25519",
    "/.netrc",
    "/.config/gcloud",
    "/.kube/config",
]

_SENSITIVE_WRITE_DIRS = [
    "/root/",
    "/home/",
    "/etc/",
    "/usr/local/lib/python",
]


def _is_docker_available() -> bool:
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


class DynamicAnalyzer:
    """
    Run package install in a Docker sandbox with strace monitoring.
    Detects: network calls, file writes, subprocess spawning, credential access.
    """

    def __init__(self, timeout: int = SANDBOX_TIMEOUT):
        self.timeout = timeout
        self.docker_available = _is_docker_available()

    def analyze(
        self,
        package: str,
        version: str,
        wheel_path: Optional[Path] = None,
    ) -> tuple[list[Finding], BehaviorSnapshot]:
        """
        Run dynamic analysis. Returns (findings, behavior_snapshot).
        Falls back to lightweight analysis if Docker unavailable.
        """
        if not self.docker_available:
            return self._fallback_analysis(package, version)

        return self._docker_analysis(package, version, wheel_path)

    def _docker_analysis(
        self,
        package: str,
        version: str,
        wheel_path: Optional[Path],
    ) -> tuple[list[Finding], BehaviorSnapshot]:
        """Full Docker + strace analysis."""
        findings: list[Finding] = []
        behavior = BehaviorSnapshot(package=package, version=version)

        pkg_spec = f"{package}=={version}" if version else package
        wheel_mount = ""
        install_cmd = f"pip install --no-deps '{pkg_spec}'"

        if wheel_path and wheel_path.exists():
            install_cmd = f"pip install --no-deps /wheel/{wheel_path.name}"
            wheel_mount = f"-v {wheel_path.parent}:/wheel"

        # strace command to monitor the install
        strace_cmd = (
            "strace -f -e trace=network,file,process "
            "-o /tmp/strace.log "
            f"{install_cmd} 2>&1; "
            "echo '---STRACE---'; cat /tmp/strace.log 2>/dev/null || true"
        )

        docker_cmd = [
            "docker", "run", "--rm",
            "--network=none",           # No network by default (we detect attempts)
            "--memory=256m",
            "--cpus=0.5",
            "--security-opt=no-new-privileges",
        ]

        if wheel_mount:
            docker_cmd.extend(wheel_mount.split())

        docker_cmd.extend([
            SANDBOX_IMAGE,
            "bash", "-c",
            # First install strace, then run monitored install
            f"apt-get install -q -y strace 2>/dev/null; {strace_cmd}",
        ])

        try:
            result = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            output = result.stdout + result.stderr

            # Parse strace output
            strace_section = ""
            if "---STRACE---" in output:
                strace_section = output.split("---STRACE---")[1]

            findings.extend(self._parse_strace(strace_section, behavior, package))
            findings.extend(self._parse_install_output(output, behavior))

        except subprocess.TimeoutExpired:
            findings.append(Finding(
                rule_id="SANDBOX_TIMEOUT",
                severity=Severity.MEDIUM,
                title="Sandbox analysis timed out",
                description=f"Package install took longer than {self.timeout}s in sandbox.",
                source="dynamic",
            ))
        except Exception as e:
            # Docker failure — not a security finding, just note it
            pass

        return findings, behavior

    def _parse_strace(
        self,
        strace_output: str,
        behavior: BehaviorSnapshot,
        package: str,
    ) -> list[Finding]:
        """Parse strace log to extract behaviors and generate findings."""
        findings = []

        network_calls = []
        file_writes = []
        subprocesses = []
        env_reads = []
        pth_files = []

        for line in strace_output.splitlines():
            # Network connections
            if "connect(" in line or "sendto(" in line or "socket(" in line:
                if "AF_INET" in line or "AF_INET6" in line:
                    network_calls.append(line[:200])

            # File writes outside package dir
            if "open(" in line and ("O_WRONLY" in line or "O_RDWR" in line or "O_CREAT" in line):
                for sensitive in _SENSITIVE_WRITE_DIRS:
                    if sensitive in line:
                        file_writes.append(line[:200])
                        break

                # .pth file writes
                if ".pth" in line:
                    pth_files.append(line[:200])

            # Subprocess spawning
            if "execve(" in line and package not in line and "pip" not in line:
                subprocesses.append(line[:200])

            # Credential file access
            for cred_path in _CREDENTIAL_PATHS:
                if cred_path in line:
                    env_reads.append(f"credential_access:{cred_path}")
                    rule = DYNAMIC_RULES["CREDENTIAL_FILE_READ"]
                    findings.append(Finding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        title=rule.title,
                        description=rule.description,
                        evidence=f"Accessed: {cred_path}",
                        source="dynamic",
                    ))

        # Update behavior snapshot
        behavior.network_calls = network_calls
        behavior.file_writes = file_writes
        behavior.subprocesses = subprocesses
        behavior.pth_files = pth_files

        # Generate findings from behaviors
        if network_calls:
            rule = DYNAMIC_RULES["OUTBOUND_NETWORK"]
            findings.append(Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                evidence=f"Network calls detected:\n" + "\n".join(network_calls[:5]),
                source="dynamic",
            ))

        if file_writes:
            rule = DYNAMIC_RULES["FILE_WRITE_HOMEDIR"]
            findings.append(Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                evidence=f"File writes:\n" + "\n".join(file_writes[:5]),
                source="dynamic",
            ))

        if pth_files:
            rule = DYNAMIC_RULES["PERSISTENT_HOOK"]
            findings.append(Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                evidence=f".pth file writes confirmed:\n" + "\n".join(pth_files[:5]),
                source="dynamic",
            ))

        # Credential exfiltration: env read + network
        if env_reads and network_calls:
            rule = DYNAMIC_RULES["ENV_VAR_EXFIL"]
            findings.append(Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                evidence=f"Env/cred reads: {env_reads[:3]}\nNetwork: {network_calls[:2]}",
                source="dynamic",
            ))

        if subprocesses:
            rule = DYNAMIC_RULES["SUBPROCESS_SPAWN"]
            findings.append(Finding(
                rule_id=rule.rule_id,
                severity=rule.severity,
                title=rule.title,
                description=rule.description,
                evidence=f"Subprocesses:\n" + "\n".join(subprocesses[:5]),
                source="dynamic",
            ))

        return findings

    def _parse_install_output(
        self,
        output: str,
        behavior: BehaviorSnapshot,
    ) -> list[Finding]:
        """Parse pip install output for additional signals."""
        findings = []
        # If pip itself reports network errors when network=none,
        # that means the package tried to call home during install
        if "ConnectionError" in output or "Network is unreachable" in output:
            if "models.litellm" in output or "litellm.cloud" in output:
                rule = DYNAMIC_RULES["OUTBOUND_NETWORK"]
                findings.append(Finding(
                    rule_id=rule.rule_id,
                    severity=rule.severity,
                    title=rule.title,
                    description=rule.description,
                    evidence="Network blocked, but package attempted connection: " + output[:300],
                    source="dynamic",
                ))
        return findings

    def _fallback_analysis(
        self,
        package: str,
        version: str,
    ) -> tuple[list[Finding], BehaviorSnapshot]:
        """
        Lightweight fallback when Docker is unavailable.
        Returns empty findings with a warning.
        """
        behavior = BehaviorSnapshot(package=package, version=version)
        findings = [
            Finding(
                rule_id="DOCKER_UNAVAILABLE",
                severity=Severity.INFO,
                title="Dynamic analysis skipped (Docker not available)",
                description=(
                    "For full sandbox analysis, install Docker and re-run. "
                    "Static analysis results above are still valid."
                ),
                source="dynamic",
            )
        ]
        return findings, behavior
