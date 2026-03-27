"""check command -- scan a package without installing."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click

from chaincanary import reporter
from chaincanary.cli._helpers import _parse_package_spec, _resolve_version, _run_analysis
from chaincanary.cli._main import main


@main.command()
@click.argument("package_spec")
@click.option(
    "--skip-dynamic", is_flag=True, help="Static analysis only (faster, no Docker needed)"
)
@click.option("--verbose", "-v", is_flag=True, help="Show detailed evidence for each finding")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON (for CI/CD)")
@click.option(
    "--local", "-l", "local_wheel",
    type=click.Path(exists=True),
    help="Scan a local .whl file instead of downloading from PyPI",
)
@click.option(
    "--sarif-output", is_flag=True,
    help="Output as SARIF v2.1.0 (for GitHub Code Scanning)",
)
@click.option(
    "--offline", is_flag=True,
    help="No network calls. Requires --local for check.",
)
@click.option(
    "--timeout", type=click.IntRange(min=1, max=300),
    default=30, show_default=True,
    help="Per-request timeout in seconds (1\u2013300).",
)
@click.option(
    "--internal-names", default="",
    help=(
        "Comma-separated internal package names for "
        "dependency confusion detection."
    ),
)
def check(
    package_spec: str,
    skip_dynamic: bool,
    verbose: bool,
    json_output: bool,
    local_wheel: str | None,
    sarif_output: bool,
    offline: bool,
    timeout: int,
    internal_names: str,
):
    """
    Check a package for security issues WITHOUT installing it.

    \b
    Examples:
        chaincanary check litellm==1.82.7
        chaincanary check litellm==1.82.7 --verbose
        chaincanary check requests --json-output
        chaincanary check litellm==1.82.8 --local ./litellm-1.82.8-py3-none-any.whl
    """
    package, version = _parse_package_spec(package_spec)

    if offline and not local_wheel:
        reporter.print_error(
            "--offline requires --local <path.whl>. "
            "Provide a local wheel file to scan."
        )
        sys.exit(1)

    if not local_wheel and not offline:
        version = _resolve_version(package, version)
    elif not version:
        # Extract version from wheel filename if not provided
        whl_name = Path(local_wheel or "").stem
        parts = whl_name.split("-")
        version = parts[1] if len(parts) >= 2 else "unknown"

    # Parse internal names
    int_names = {
        s.strip().lower()
        for s in internal_names.split(",")
        if s.strip()
    }

    report = _run_analysis(
        package, version, skip_dynamic=skip_dynamic, verbose=verbose,
        quiet=json_output or sarif_output,
        local_wheel=local_wheel,
        offline=offline,
        timeout=timeout,
        internal_names_set=int_names or None,
    )

    if sarif_output:
        from chaincanary.sarif import report_to_sarif

        click.echo(json.dumps(report_to_sarif(report), indent=2))
        sys.exit(1 if report.is_blocked else 0)

    if json_output:
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
            ],
            "behavior_diff": report.behavior_diff,
        }
        click.echo(json.dumps(output, indent=2))
        sys.exit(1 if report.is_blocked else 0)

    reporter.print_report(report)

    if verbose:
        for finding in report.findings:
            if finding.evidence:
                reporter.print_detail(finding)

    sys.exit(1 if report.is_blocked else 0)
