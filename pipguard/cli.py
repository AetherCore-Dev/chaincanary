"""
CLI entry point for pipguard.
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from pipguard.models import RiskReport
from pipguard.analyzer.static import StaticAnalyzer
from pipguard.analyzer.dynamic import DynamicAnalyzer
from pipguard.downloader import download_wheel, get_latest_safe_version
from pipguard import reporter

console = Console()


def _run_analysis(
    package: str,
    version: str,
    skip_dynamic: bool = False,
    verbose: bool = False,
) -> RiskReport:
    """Core analysis pipeline."""
    reporter.print_scanning(package, version)

    report = RiskReport(package=package, version=version)

    with tempfile.TemporaryDirectory(prefix="pipguard_") as tmpdir:
        tmp_path = Path(tmpdir)

        # Download wheel
        console.print("  [dim]→ Downloading package (not installing)...[/dim]")
        wheel_path = download_wheel(package, version, tmp_path)
        if not wheel_path:
            reporter.print_error(
                f"Could not download {package}=={version} from PyPI. "
                "Check the package name and version."
            )
            sys.exit(1)

        console.print(f"  [dim]→ Downloaded: {wheel_path.name}[/dim]")

        # Static analysis
        reporter.print_static_start()
        static = StaticAnalyzer()
        static_findings = static.analyze_wheel(wheel_path)
        report.findings.extend(static_findings)
        report.calculate_score()

        if verbose and static_findings:
            for f in static_findings:
                reporter.print_detail(f)

        # Dynamic analysis (skip if static score is very low OR --skip-dynamic)
        if not skip_dynamic and report.score > 0:
            reporter.print_dynamic_start()
            dynamic = DynamicAnalyzer()
            dynamic_findings, behavior = dynamic.analyze(package, version, wheel_path)
            report.findings.extend([f for f in dynamic_findings if f.rule_id != "DOCKER_UNAVAILABLE"])
            report.behavior = behavior
            report.calculate_score()

            if verbose and dynamic_findings:
                for f in dynamic_findings:
                    reporter.print_detail(f)

        # Get safe version suggestion if needed
        if report.verdict in ("HIGH_RISK", "MALICIOUS"):
            report.safe_version = get_latest_safe_version(package, version)

    return report


@click.group()
@click.version_option()
def main():
    """
    pipguard — pip installation security sandbox.

    Detects supply chain attacks before they compromise your system.

    \b
    Example:
        pipguard install litellm==1.82.7
        pipguard check numpy==1.24.0
        pipguard scan requests
    """
    pass


@main.command()
@click.argument("package_spec")
@click.option("--skip-dynamic", is_flag=True, help="Skip Docker sandbox analysis (faster)")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed findings with evidence")
@click.option("--force", is_flag=True, help="Install even if malicious (not recommended)")
@click.option("--json-output", is_flag=True, help="Output results as JSON")
@click.option("--block-on", default="MALICIOUS", 
              type=click.Choice(["HIGH_RISK", "MALICIOUS"]),
              help="Set minimum verdict level to block (default: MALICIOUS)")
def install(
    package_spec: str,
    skip_dynamic: bool,
    verbose: bool,
    force: bool,
    json_output: bool,
    block_on: str,
):
    """
    Analyze and install a package safely.

    PACKAGE_SPEC can be:
        litellm==1.82.7
        requests>=2.28
        numpy

    pipguard will analyze the package before installing it.
    """
    # Parse package spec
    import re
    match = re.match(r"^([A-Za-z0-9_\-\.]+)(?:==([^\s]+))?", package_spec)
    if not match:
        reporter.print_error(f"Invalid package spec: {package_spec}")
        sys.exit(1)

    package = match.group(1)
    version = match.group(2)

    if not version:
        # Get latest version
        from pipguard.downloader import get_all_versions
        from packaging.version import Version, InvalidVersion
        versions = get_all_versions(package)
        if not versions:
            reporter.print_error(f"Package '{package}' not found on PyPI.")
            sys.exit(1)
        parsed = []
        for v in versions:
            try:
                parsed.append(Version(v))
            except InvalidVersion:
                pass
        version = str(max(parsed))
        console.print(f"  [dim]→ Latest version: {version}[/dim]")

    report = _run_analysis(package, version, skip_dynamic=skip_dynamic, verbose=verbose)

    if json_output:
        import json
        output = {
            "package": package,
            "version": version,
            "score": report.score,
            "verdict": report.verdict,
            "safe_version": report.safe_version,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "source": f.source,
                }
                for f in report.findings
            ]
        }
        click.echo(json.dumps(output, indent=2))
        sys.exit(1 if report.is_blocked and not force else 0)

    reporter.print_report(report)

    # Decide whether to proceed with install
    should_block = (
        (block_on == "MALICIOUS" and report.is_blocked) or
        (block_on == "HIGH_RISK" and report.score > 4.0)
    )

    if should_block and not force:
        reporter.print_error(
            f"Installation of {package}=={version} was BLOCKED.\n"
            + (f"Consider: pip install {package}=={report.safe_version}" if report.safe_version else "")
        )
        sys.exit(1)

    if not should_block or force:
        import subprocess
        console.print(f"[dim]Installing {package}=={version} via pip...[/dim]")
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", f"{package}=={version}"],
            check=False,
        )
        if result.returncode == 0:
            reporter.print_success(f"Installed {package}=={version}")
        else:
            reporter.print_error("pip install failed.")
            sys.exit(result.returncode)


@main.command()
@click.argument("package_spec")
@click.option("--skip-dynamic", is_flag=True, help="Skip Docker sandbox analysis")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed evidence")
@click.option("--json-output", is_flag=True, help="Output as JSON (for CI)")
def check(
    package_spec: str,
    skip_dynamic: bool,
    verbose: bool,
    json_output: bool,
):
    """
    Check a package for security issues WITHOUT installing it.

    \b
    Examples:
        pipguard check litellm==1.82.7
        pipguard check requests
    """
    import re
    match = re.match(r"^([A-Za-z0-9_\-\.]+)(?:==([^\s]+))?", package_spec)
    if not match:
        reporter.print_error(f"Invalid package spec: {package_spec}")
        sys.exit(1)

    package = match.group(1)
    version = match.group(2)

    if not version:
        from pipguard.downloader import get_all_versions
        from packaging.version import Version, InvalidVersion
        versions = get_all_versions(package)
        if not versions:
            reporter.print_error(f"Package '{package}' not found on PyPI.")
            sys.exit(1)
        parsed = []
        for v in versions:
            try:
                parsed.append(Version(v))
            except InvalidVersion:
                pass
        version = str(max(parsed))

    report = _run_analysis(package, version, skip_dynamic=skip_dynamic, verbose=verbose)

    if json_output:
        import json
        output = {
            "package": package,
            "version": version,
            "score": report.score,
            "verdict": report.verdict,
            "safe_version": report.safe_version,
            "findings_count": len(report.findings),
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "title": f.title,
                    "source": f.source,
                }
                for f in report.findings
            ]
        }
        click.echo(json.dumps(output, indent=2))
        sys.exit(1 if report.is_blocked else 0)

    reporter.print_report(report)
    sys.exit(1 if report.is_blocked else 0)


if __name__ == "__main__":
    main()
