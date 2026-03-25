"""
Main analysis engine — orchestrates static, dynamic, and diff analysis.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional

from rich.console import Console

from pipguard.models import RiskReport, Finding, Severity
from pipguard.analyzer.static import StaticAnalyzer
from pipguard.analyzer.dynamic import DynamicAnalyzer
from pipguard.analyzer.differ import diff_from_static
from pipguard.downloader import download_wheel, get_latest_safe_version

console = Console(stderr=True)


class AnalysisEngine:
    def __init__(
        self,
        skip_dynamic: bool = False,
        verbose: bool = False,
    ):
        self.skip_dynamic = skip_dynamic
        self.verbose = verbose
        self.static = StaticAnalyzer()
        self.dynamic = DynamicAnalyzer()

    def analyze(
        self,
        package: str,
        version: str,
        on_progress=None,
    ) -> RiskReport:
        """
        Full analysis pipeline for a package.
        on_progress: optional callback(step: str)
        """
        report = RiskReport(package=package, version=version)

        def progress(msg: str):
            if on_progress:
                on_progress(msg)

        with tempfile.TemporaryDirectory(prefix="pipguard_") as tmpdir:
            tmp_path = Path(tmpdir)

            # ── Step 1: Download ─────────────────────────────────────
            progress("Downloading package...")
            wheel_path = download_wheel(package, version, tmp_path)
            if not wheel_path:
                report.findings.append(Finding(
                    rule_id="DOWNLOAD_FAILED",
                    severity=Severity.INFO,
                    title=f"Could not download {package}=={version}",
                    description="Package not found on PyPI or network error.",
                    source="static",
                ))
                report.calculate_score()
                return report

            # ── Step 2: Static Analysis ──────────────────────────────
            progress("Running static analysis...")
            static_findings = self.static.analyze_wheel(wheel_path)
            report.findings.extend(static_findings)
            report.calculate_score()

            # ── Step 3: Version Diff (fast, always run) ──────────────
            progress("Comparing with previous version...")
            curr_files = self.static.get_wheel_filelist(wheel_path)
            prev_wheel = self._get_prev_version_wheel(package, version, tmp_path)
            if prev_wheel:
                prev_files = self.static.get_wheel_filelist(prev_wheel)
                file_diff = diff_from_static(prev_files, curr_files)
                report.behavior_diff = file_diff

                # New .pth files are a critical signal even if static missed them
                if file_diff.get("new_pth_files"):
                    already_reported = any(
                        f.rule_id == "PTH_FILE_INSTALL" for f in report.findings
                    )
                    if not already_reported:
                        from pipguard.analyzer.rules import STATIC_RULES
                        rule = STATIC_RULES["PTH_FILE_INSTALL"]
                        report.findings.append(Finding(
                            rule_id="PTH_FILE_NEW_IN_VERSION",
                            severity=Severity.CRITICAL,
                            title=".pth file ADDED in this version (not in previous)",
                            description=(
                                f"This version introduced a new .pth file that "
                                f"was NOT present in the previous version. "
                                f"This is the exact attack vector used in LiteLLM 1.82.7."
                            ),
                            evidence=(
                                f"New files: {file_diff['new_pth_files']}\n"
                                f"Previous version did not contain these files."
                            ),
                            source="static",
                        ))
                        report.calculate_score()

                # Suspicious new files
                if file_diff.get("new_suspicious_files"):
                    report.findings.append(Finding(
                        rule_id="SUSPICIOUS_NEW_FILES",
                        severity=Severity.HIGH,
                        title="Suspicious new files added in this version",
                        description="Files with suspicious names were added compared to the previous version.",
                        evidence=f"New suspicious files: {file_diff['new_suspicious_files']}",
                        source="static",
                    ))
                    report.calculate_score()

            # ── Step 4: Dynamic Analysis ─────────────────────────────
            if not self.skip_dynamic and report.score > 0:
                progress("Running sandbox analysis...")
                dynamic_findings, behavior = self.dynamic.analyze(
                    package, version, wheel_path
                )
                report.behavior = behavior
                # Filter out info-level docker unavailable notice from findings
                real_findings = [
                    f for f in dynamic_findings
                    if f.rule_id not in ("DOCKER_UNAVAILABLE",)
                ]
                report.findings.extend(real_findings)
                report.calculate_score()

            # ── Step 5: Safe version lookup ──────────────────────────
            if report.verdict in ("HIGH_RISK", "MALICIOUS"):
                progress("Looking up safe version...")
                report.safe_version = get_latest_safe_version(package, version)

        return report

    def _get_prev_version_wheel(
        self,
        package: str,
        current_version: str,
        tmp_path: Path,
    ) -> Optional[Path]:
        """Download the previous version for comparison."""
        try:
            prev_version = get_latest_safe_version(package, current_version)
            if not prev_version:
                return None
            prev_dir = tmp_path / "prev"
            prev_dir.mkdir(exist_ok=True)
            return download_wheel(package, prev_version, prev_dir)
        except Exception:
            return None
