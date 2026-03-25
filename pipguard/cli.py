"""
CLI entry point for pipguard.
"""
from __future__ import annotations

import json
import re
import sys
import subprocess
import concurrent.futures
from typing import Optional

import click
from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
from rich.text import Text
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box

from pipguard.engine import AnalysisEngine
from pipguard import reporter

console = Console()


def _parse_package_spec(spec: str) -> tuple[str, Optional[str]]:
    """Parse 'requests==2.28.0' or 'requests' into (name, version|None)."""
    m = re.match(r"^([A-Za-z0-9_\-\.]+)(?:==([^\s,;]+))?", spec)
    if not m:
        reporter.print_error(f"Invalid package spec: {spec}")
        sys.exit(1)
    return m.group(1), m.group(2)


def _resolve_version(package: str, version: Optional[str]) -> str:
    """If version is None, resolve to latest from PyPI."""
    if version:
        return version
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
    if not parsed:
        reporter.print_error(f"No valid versions found for '{package}'.")
        sys.exit(1)
    latest = str(max(parsed))
    console.print(f"  [dim]→ Resolving to latest: {latest}[/dim]")
    return latest


def _run_analysis(
    package: str,
    version: str,
    skip_dynamic: bool = False,
    verbose: bool = False,
    quiet: bool = False,       # suppress spinner (e.g., JSON mode or batch)
):
    """Run full analysis with live progress display."""
    if not quiet:
        reporter.print_scanning(package, version)

    engine = AnalysisEngine(skip_dynamic=skip_dynamic, verbose=verbose)

    if quiet or not console.is_terminal:
        # JSON / piped output — no spinner, no color pollution
        report = engine.analyze(package, version)
    else:
        status_text = Text("Starting...", style="dim")
        with Live(
            Spinner("dots", text=status_text),
            console=console,
            transient=True,
            refresh_per_second=10,
        ):
            def on_progress(msg: str):
                status_text.plain = f"  {msg}"
            report = engine.analyze(package, version, on_progress=on_progress)

    return report


@click.group()
@click.version_option(prog_name="pipguard")
def main():
    """
    \b
    pipguard — pip installation security sandbox
    Detects supply chain attacks before they compromise your system.

    \b
    Quick start:
        pipguard check litellm==1.82.7
        pipguard install requests
    """
    pass


@main.command()
@click.argument("package_spec")
@click.option("--skip-dynamic", is_flag=True, help="Static analysis only (faster, no Docker needed)")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed evidence for each finding")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON (for CI/CD)")
def check(package_spec: str, skip_dynamic: bool, verbose: bool, json_output: bool):
    """
    Check a package for security issues WITHOUT installing it.

    \b
    Examples:
        pipguard check litellm==1.82.7
        pipguard check litellm==1.82.7 --verbose
        pipguard check requests --json-output
    """
    package, version = _parse_package_spec(package_spec)
    version = _resolve_version(package, version)

    report = _run_analysis(package, version, skip_dynamic=skip_dynamic, verbose=verbose,
                           quiet=json_output)

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


@main.command()
@click.argument("package_spec")
@click.option("--skip-dynamic", is_flag=True, help="Static analysis only (faster)")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed evidence")
@click.option("--force", is_flag=True, help="Install even if blocked (not recommended)")
@click.option("--block-on", default="MALICIOUS",
              type=click.Choice(["HIGH_RISK", "MALICIOUS"]),
              help="Minimum verdict to block installation (default: MALICIOUS)")
@click.option("--json-output", "-j", is_flag=True, help="Output results as JSON")
def install(
    package_spec: str,
    skip_dynamic: bool,
    verbose: bool,
    force: bool,
    block_on: str,
    json_output: bool,
):
    """
    Analyze a package and install it if safe.

    \b
    Examples:
        pipguard install litellm==1.82.7
        pipguard install litellm --block-on HIGH_RISK
        pipguard install litellm==1.82.7 --force  # override block
    """
    package, version = _parse_package_spec(package_spec)
    version = _resolve_version(package, version)

    report = _run_analysis(package, version, skip_dynamic=skip_dynamic, verbose=verbose)

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
    should_block = (
        (block_on == "MALICIOUS" and report.is_blocked) or
        (block_on == "HIGH_RISK" and report.score > 4.0)
    )

    if should_block and not force:
        msg = f"Installation of [bold]{package}=={version}[/bold] was BLOCKED."
        if report.safe_version:
            msg += f"\n  Try: [bold green]pip install {package}=={report.safe_version}[/bold green]"
        console.print(f"\n[bold red]🚫 {msg}[/bold red]\n")
        sys.exit(1)

    # Proceed with install
    if should_block and force:
        console.print("[bold yellow]⚠️  --force override: proceeding despite security risk[/bold yellow]")

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


@main.command()
@click.argument("lockfile", default="requirements.txt")
@click.option("--skip-dynamic", is_flag=True, help="Static analysis only (faster)")
@click.option("--workers", default=4, show_default=True, help="Parallel scan workers")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
@click.option("--fail-on", default="MALICIOUS",
              type=click.Choice(["HIGH_RISK", "MALICIOUS"]),
              help="Exit with error code if any package hits this verdict")
def audit(lockfile: str, skip_dynamic: bool, workers: int, json_output: bool, fail_on: str):
    """
    Audit all packages in a lockfile / requirements file.

    \b
    Examples:
        pipguard audit
        pipguard audit requirements.txt
        pipguard audit pyproject.toml --fail-on HIGH_RISK
        pipguard audit requirements.txt --json-output | jq '.results[] | select(.verdict != "SAFE")'
    """
    from pipguard.lockfile import parse_lockfile, detect_lockfile
    from pipguard.downloader import get_all_versions
    from packaging.version import Version, InvalidVersion

    # Cap workers to avoid PyPI rate-limiting (429 Too Many Requests)
    safe_workers = max(1, min(workers, 16))
    if workers > 16:
        reporter.print_warning(
            f"--workers {workers} capped to 16 to avoid PyPI rate-limits."
        )

    lock_path = Path(lockfile) if lockfile != "requirements.txt" else Path(lockfile)
    if not lock_path.exists():
        # Try auto-detect
        detected = detect_lockfile(Path("."))
        if detected:
            lock_path = detected
            console.print(f"[dim]Auto-detected: {lock_path}[/dim]")
        else:
            reporter.print_error(f"File not found: {lockfile}")
            sys.exit(1)

    specs = parse_lockfile(lock_path)
    if not specs:
        reporter.print_error(f"No packages found in {lock_path}")
        sys.exit(1)

    console.print(f"\n[bold cyan]🔍 pipguard audit[/bold cyan] — {lock_path} ({len(specs)} packages)\n")

    results = []
    engine = AnalysisEngine(skip_dynamic=skip_dynamic)

    def scan_one(spec):
        # ── Git dependencies: flag immediately, don't scan PyPI ──────
        if spec.is_git_dep:
            return {
                "package": spec.name,
                "version": "git",
                "score": 5.0,
                "verdict": "HIGH_RISK",
                "safe_version": None,
                "findings": [{
                    "rule_id": "GIT_DEPENDENCY",
                    "severity": "HIGH",
                    "title": f"Git dependency bypasses PyPI review: {spec.git_url or spec.name}",
                }],
            }

        version = spec.version
        if not version:
            # Resolve latest
            try:
                versions = get_all_versions(spec.name)
                parsed = sorted(
                    [Version(v) for v in versions
                     if not Version(v).is_prerelease],
                    reverse=True
                )
                version = str(parsed[0]) if parsed else None
            except Exception:
                version = None

        if not version:
            return {
                "package": spec.name,
                "version": "unknown",
                "score": 0,
                "verdict": "UNKNOWN",
                "findings": [],
            }

        report = engine.analyze(spec.name, version)
        return {
            "package": spec.name,
            "version": version,
            "score": report.score,
            "verdict": report.verdict,
            "safe_version": report.safe_version,
            "findings": [
                {"rule_id": f.rule_id, "severity": f.severity.value, "title": f.title}
                for f in report.findings
            ],
        }

    # Parallel scan with progress bar
    if json_output or not console.is_terminal:
        with concurrent.futures.ThreadPoolExecutor(max_workers=safe_workers) as ex:
            futures = {ex.submit(scan_one, s): s for s in specs}
            for fut in concurrent.futures.as_completed(futures):
                results.append(fut.result())
    else:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning packages...", total=len(specs))
            with concurrent.futures.ThreadPoolExecutor(max_workers=safe_workers) as ex:
                futures = {ex.submit(scan_one, s): s for s in specs}
                for fut in concurrent.futures.as_completed(futures):
                    result = fut.result()
                    results.append(result)
                    progress.advance(task)
                    if result["verdict"] in ("MALICIOUS", "HIGH_RISK"):
                        progress.print(
                            f"  [red]⚠  {result['package']}=={result['version']} "
                            f"— {result['verdict']}[/red]"
                        )

    # Sort by risk score descending
    results.sort(key=lambda r: r["score"], reverse=True)

    if json_output:
        click.echo(json.dumps({"lockfile": str(lock_path), "results": results}, indent=2))
    else:
        _print_audit_table(results)

    # Exit code
    risky = [r for r in results if r["verdict"] in (
        ["MALICIOUS"] if fail_on == "MALICIOUS" else ["MALICIOUS", "HIGH_RISK"]
    )]
    if risky:
        console.print(f"[bold red]✗ {len(risky)} package(s) failed the audit.[/bold red]\n")
        sys.exit(1)
    else:
        console.print(f"[bold green]✓ All {len(results)} packages passed audit.[/bold green]\n")


def _print_audit_table(results: list[dict]) -> None:
    table = Table(
        box=box.ROUNDED,
        title="Audit Results",
        show_header=True,
        header_style="bold",
    )
    table.add_column("Package", ratio=2)
    table.add_column("Version", width=12)
    table.add_column("Score", width=7, justify="right")
    table.add_column("Verdict", width=12)
    table.add_column("Top Finding", ratio=3)

    verdict_colors = {
        "SAFE": "green",
        "LOW_RISK": "yellow",
        "HIGH_RISK": "orange3",
        "MALICIOUS": "bold red",
        "UNKNOWN": "dim",
    }

    for r in results:
        color = verdict_colors.get(r["verdict"], "white")
        top = r["findings"][0]["title"][:45] if r["findings"] else "—"
        table.add_row(
            r["package"],
            r["version"],
            f"{r['score']:.1f}",
            f"[{color}]{r['verdict']}[/{color}]",
            f"[dim]{top}[/dim]" if r["verdict"] == "SAFE" else top,
        )

    console.print()
    console.print(table)
    console.print()


# Needed by audit command
from pathlib import Path


@main.command()
@click.argument("package")
@click.argument("version_a")
@click.argument("version_b")
@click.option("--json-output", "-j", is_flag=True)
def diff(package: str, version_a: str, version_b: str, json_output: bool):
    """
    Compare two versions of a package for behavioral changes.

    \b
    Example:
        pipguard diff litellm 1.82.6 1.82.7

    This shows exactly what changed between versions — new files,
    new network behavior, new persistence mechanisms.
    """
    import tempfile
    from pathlib import Path
    from pipguard.downloader import download_wheel
    from pipguard.analyzer.static import StaticAnalyzer
    from pipguard.analyzer.differ import diff_from_static

    console.print(
        f"\n[bold cyan]🔍 pipguard diff[/bold cyan] — "
        f"[bold]{package}[/bold] "
        f"[dim]{version_a}[/dim] → [bold]{version_b}[/bold]\n"
    )

    static = StaticAnalyzer()

    with tempfile.TemporaryDirectory(prefix="pipguard_diff_") as tmpdir:
        tmp = Path(tmpdir)

        console.print(f"[dim]Downloading {package}=={version_a}...[/dim]")
        wheel_a = download_wheel(package, version_a, tmp / "a")

        console.print(f"[dim]Downloading {package}=={version_b}...[/dim]")
        wheel_b = download_wheel(package, version_b, tmp / "b")

        if not wheel_a or not wheel_b:
            reporter.print_error("Could not download one or both versions.")
            sys.exit(1)

        files_a = static.get_wheel_filelist(wheel_a)
        files_b = static.get_wheel_filelist(wheel_b)
        result = diff_from_static(files_a, files_b)

    if json_output:
        click.echo(json.dumps(result, indent=2))
        sys.exit(0)

    # Pretty print
    added = result.get("added_files", [])
    removed = result.get("removed_files", [])
    new_pth = result.get("new_pth_files", [])
    new_sus = result.get("new_suspicious_files", [])

    if not added and not removed:
        console.print("[green]✓ No file-level changes between versions.[/green]\n")
        sys.exit(0)

    from rich.table import Table
    from rich import box

    table = Table(box=box.ROUNDED, title=f"File changes: {package} {version_a} → {version_b}")
    table.add_column("Change", width=8)
    table.add_column("File", ratio=1)
    table.add_column("Risk", width=12)

    for f in new_pth:
        table.add_row("[bold red]ADDED[/bold red]", f, "[bold red]⚠ .pth file[/bold red]")
    for f in new_sus:
        if f not in new_pth:
            table.add_row("[red]ADDED[/red]", f, "[yellow]suspicious name[/yellow]")
    for f in added:
        if f not in new_pth and f not in new_sus:
            table.add_row("[green]added[/green]", f, "")
    for f in removed:
        table.add_row("[dim]removed[/dim]", f, "")

    console.print(table)

    if new_pth:
        console.print(
            f"\n[bold red]☠️  CRITICAL: New .pth file(s) detected![/bold red]\n"
            f"  {new_pth}\n"
            f"  This is the exact attack vector used in the LiteLLM 1.82.7 supply chain attack.\n"
        )
        sys.exit(1)

    console.print()
    sys.exit(0)


if __name__ == "__main__":
    main()
