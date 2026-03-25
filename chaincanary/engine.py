"""
Main analysis engine — orchestrates static, dynamic, and diff analysis.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from rich.console import Console

from chaincanary.analyzer.differ import diff_from_static
from chaincanary.analyzer.dynamic import DynamicAnalyzer
from chaincanary.analyzer.static import StaticAnalyzer
from chaincanary.downloader import download_wheel, get_latest_safe_version
from chaincanary.models import Finding, RiskReport, Severity
from chaincanary.safety_checks import check_typosquatting

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
        report = RiskReport(package=package, version=version)

        def progress(msg: str):
            if on_progress:
                on_progress(msg)

        # ── Step 0: Typosquatting check (no download needed) ─────────
        typo = check_typosquatting(package)
        if typo:
            report.findings.append(
                Finding(
                    rule_id="TYPOSQUATTING",
                    severity=Severity.HIGH if typo["likely_typosquat"] else Severity.MEDIUM,
                    title=f"Package name resembles '{typo['target']}' (edit distance: {typo['distance']})",
                    description=(
                        f"'{package}' is suspiciously similar to the popular package "
                        f"'{typo['target']}' (similarity: {typo['similarity']:.0%}, "
                        f"edit distance: {typo['distance']}). "
                        "Typosquatting is a common supply chain attack vector — "
                        "verify you spelled the package name correctly."
                    ),
                    evidence=f"Input: {package!r}  →  Popular package: {typo['target']!r}",
                    source="static",
                )
            )
            report.calculate_score()

        with tempfile.TemporaryDirectory(prefix="chaincanary_") as tmpdir:
            tmp_path = Path(tmpdir)

            # ── Step 1: Download ─────────────────────────────────────
            progress("Downloading package...")
            wheel_path = download_wheel(package, version, tmp_path)
            if not wheel_path:
                report.findings.append(
                    Finding(
                        rule_id="DOWNLOAD_FAILED",
                        severity=Severity.INFO,
                        title=f"Could not download {package}=={version}",
                        description="Package not found on PyPI or network error.",
                        source="static",
                    )
                )
                report.calculate_score()
                return report

            # ── Step 2: Static Analysis ──────────────────────────────
            progress("Running static analysis...")
            static_findings = self.static.analyze_wheel(wheel_path, package)
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

                if file_diff.get("new_pth_files"):
                    already_reported = any(f.rule_id == "PTH_FILE_INSTALL" for f in report.findings)
                    if not already_reported:
                        report.findings.append(
                            Finding(
                                rule_id="PTH_FILE_NEW_IN_VERSION",
                                severity=Severity.CRITICAL,
                                title=".pth file ADDED in this version (not in previous)",
                                description=(
                                    "This version introduced a new .pth file that "
                                    "was NOT present in the previous version. "
                                    "This is the exact attack vector used in LiteLLM 1.82.7."
                                ),
                                evidence=(
                                    f"New files: {file_diff['new_pth_files']}\n"
                                    f"Previous version did not contain these files."
                                ),
                                source="static",
                            )
                        )
                        report.calculate_score()

                if file_diff.get("new_suspicious_files"):
                    report.findings.append(
                        Finding(
                            rule_id="SUSPICIOUS_NEW_FILES",
                            severity=Severity.HIGH,
                            title="Suspicious new files added in this version",
                            description="Files with suspicious names were added compared to the previous version.",
                            evidence=f"New suspicious files: {file_diff['new_suspicious_files']}",
                            source="static",
                        )
                    )
                    report.calculate_score()

            # ── Step 4: Dynamic Analysis ─────────────────────────────
            if not self.skip_dynamic and report.score > 0:
                progress("Running sandbox analysis...")
                dynamic_findings, behavior = self.dynamic.analyze(package, version, wheel_path)
                report.behavior = behavior
                real_findings = [
                    f for f in dynamic_findings if f.rule_id not in ("DOCKER_UNAVAILABLE",)
                ]
                report.findings.extend(real_findings)
                report.calculate_score()

            # ── Step 5: Safe version lookup + validation ─────────────
            if report.verdict in ("HIGH_RISK", "MALICIOUS"):
                progress("Finding and validating safe version...")
                report.safe_version = self._find_validated_safe_version(package, version, tmp_path)

        return report

    def _find_validated_safe_version(
        self,
        package: str,
        current_version: str,
        tmp_path: Path,
        max_candidates: int = 3,
    ) -> str | None:
        """
        Find and validate a safe rollback version.
        Unlike get_latest_safe_version(), this actually scans candidates
        to avoid recommending another compromised version.
        """
        from packaging.version import Version

        from chaincanary.downloader import get_all_versions

        try:
            all_versions = get_all_versions(package)
            current = Version(current_version)
            candidates = sorted(
                [
                    Version(v)
                    for v in all_versions
                    if not Version(v).is_prerelease and Version(v) < current
                ],
                reverse=True,
            )[:max_candidates]
        except Exception:
            return None

        for candidate in candidates:
            v_str = str(candidate)
            # Quick static scan of candidate
            try:
                cand_dir = tmp_path / f"safe_candidate_{v_str}"
                cand_dir.mkdir(exist_ok=True)
                whl = download_wheel(package, v_str, cand_dir)
                if not whl:
                    continue
                findings = self.static.analyze_wheel(whl, package)
                # Only recommend if clean or low risk
                from chaincanary.models import RiskReport as _R

                r = _R(package=package, version=v_str, findings=findings)
                r.calculate_score()
                if r.verdict in ("SAFE", "LOW_RISK"):
                    return v_str
            except Exception:
                continue

        return None  # No safe version found in recent candidates

    def _get_prev_version_wheel(
        self,
        package: str,
        current_version: str,
        tmp_path: Path,
    ) -> Path | None:
        prev_version = get_latest_safe_version(package, current_version)
        if not prev_version:
            return None
        try:
            prev_dir = tmp_path / "prev"
            prev_dir.mkdir(exist_ok=True)
            return download_wheel(package, prev_version, prev_dir)
        except Exception:
            return None
