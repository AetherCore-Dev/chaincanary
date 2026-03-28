"""install command -- scan then pip-install if safe."""

from __future__ import annotations

import json
import subprocess
import sys

import click

from chaincanary import reporter
from chaincanary.cli._helpers import (
    _parse_package_spec,
    _resolve_version,
    _run_analysis,
    console,
)
from chaincanary.cli._main import main


@main.command()
@click.argument("package_spec")
@click.option("--skip-dynamic", is_flag=True, help="Static analysis only (faster)")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed evidence")
@click.option("--force", is_flag=True, help="Install even if blocked (not recommended)")
@click.option(
    "--block-on",
    default="MALICIOUS",
    type=click.Choice(["HIGH_RISK", "MALICIOUS"]),
    help="Minimum verdict to block installation (default: MALICIOUS)",
)
@click.option("--json-output", "-j", is_flag=True, help="Output results as JSON")
@click.option(
    "--timeout", type=click.IntRange(min=1, max=300),
    default=30, show_default=True,
    help="Per-request timeout in seconds (1\u2013300).",
)
@click.option(
    "--check-attestation/--no-check-attestation",
    default=True, show_default=True,
    help="Check PyPI attestations (PEP 740).",
)
def install(
    package_spec: str,
    skip_dynamic: bool,
    verbose: bool,
    force: bool,
    block_on: str,
    json_output: bool,
    timeout: int,
    check_attestation: bool,
):
    """
    Analyze a package and install it if safe.

    \b
    Examples:
        chaincanary install litellm==1.82.7
        chaincanary install litellm --block-on HIGH_RISK
        chaincanary install litellm==1.82.7 --force  # override block
    """
    package, version = _parse_package_spec(package_spec)
    version = _resolve_version(package, version)

    report = _run_analysis(
        package, version, skip_dynamic=skip_dynamic,
        verbose=verbose, timeout=timeout,
        check_attestation=check_attestation,
    )

    if json_output:
        output = {
            "package": package,
            "version": version,
            "score": report.score,
            "verdict": report.verdict,
            "safe_version": report.safe_version,
            "blocked": report.is_blocked,
            "findings": [
                {
                    "rule_id": f.rule_id,
                    "severity": f.severity.value,
                    "title": f.title,
                }
                for f in report.findings
            ],
        }
        click.echo(json.dumps(output, indent=2))

    reporter.print_report(report)

    if verbose:
        for finding in report.findings:
            if finding.evidence:
                reporter.print_detail(finding)

    # Determine if we should block
    should_block = (block_on == "MALICIOUS" and report.is_blocked) or (
        block_on == "HIGH_RISK" and report.score > 4.0
    )

    if should_block and not force:
        msg = f"Installation of [bold]{package}=={version}[/bold] was BLOCKED."
        if report.safe_version:
            msg += f"\n  Try: [bold green]pip install {package}=={report.safe_version}[/bold green]"
        console.print(f"\n[bold red]\U0001f6ab {msg}[/bold red]\n")
        sys.exit(1)

    # Proceed with install
    if should_block and force:
        console.print(
            "[bold yellow]\u26a0\ufe0f  --force override: proceeding despite"
            " security risk[/bold yellow]"
        )

    console.print(f"[dim]Running: pip install {package}=={version}[/dim]")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", f"{package}=={version}"],
        check=False,
    )
    if result.returncode == 0:
        reporter.print_success(f"Installed {package}=={version}")
    else:
        reporter.print_error("pip install failed.")
        sys.exit(result.returncode)
