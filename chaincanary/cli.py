"""
CLI entry point for chaincanary.
"""

from __future__ import annotations

import concurrent.futures
import json
import re
import subprocess
import sys
from pathlib import Path

import click
from rich import box
from rich.console import Console
from rich.live import Live
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text

from chaincanary import reporter
from chaincanary.engine import AnalysisEngine

console = Console()
err_console = Console(stderr=True)


def _parse_package_spec(spec: str) -> tuple[str, str | None]:
    """Parse 'requests==2.28.0' or 'requests' into (name, version|None)."""
    m = re.match(r"^([A-Za-z0-9_\-\.]+)(?:==([^\s,;]+))?", spec)
    if not m:
        reporter.print_error(f"Invalid package spec: {spec}")
        sys.exit(1)
    return m.group(1), m.group(2)


def _resolve_version(package: str, version: str | None) -> str:
    """If version is None, resolve to latest from PyPI."""
    if version:
        return version
    from packaging.version import InvalidVersion, Version

    from chaincanary.downloader import get_all_versions

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
    err_console.print(f"  [dim]→ Resolving to latest: {latest}[/dim]")
    return latest


def _run_analysis(
    package: str,
    version: str,
    skip_dynamic: bool = False,
    verbose: bool = False,
    quiet: bool = False,  # suppress spinner (e.g., JSON mode or batch)
    local_wheel: str | None = None,
    offline: bool = False,
):
    """Run full analysis with live progress display."""
    if not quiet:
        reporter.print_scanning(package, version)

    engine = AnalysisEngine(
        skip_dynamic=skip_dynamic, verbose=verbose, offline=offline,
    )
    local_path = Path(local_wheel) if local_wheel else None

    if quiet or not console.is_terminal:
        # JSON / piped output — no spinner, no color pollution
        report = engine.analyze(package, version, local_wheel=local_path)
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

            report = engine.analyze(package, version, on_progress=on_progress, local_wheel=local_path)

    return report


@click.group()
@click.version_option(prog_name="chaincanary")
def main():
    """
    \b
    chaincanary — pip installation security sandbox
    Detects supply chain attacks before they compromise your system.

    \b
    Quick start:
        chaincanary check litellm==1.82.7
        chaincanary install requests
    """
    pass


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
def check(
    package_spec: str,
    skip_dynamic: bool,
    verbose: bool,
    json_output: bool,
    local_wheel: str | None,
    sarif_output: bool,
    offline: bool,
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
        whl_name = Path(local_wheel).stem
        parts = whl_name.split("-")
        version = parts[1] if len(parts) >= 2 else "unknown"

    report = _run_analysis(
        package, version, skip_dynamic=skip_dynamic, verbose=verbose,
        quiet=json_output or sarif_output,
        local_wheel=local_wheel,
        offline=offline,
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
        chaincanary install litellm==1.82.7
        chaincanary install litellm --block-on HIGH_RISK
        chaincanary install litellm==1.82.7 --force  # override block
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
    should_block = (block_on == "MALICIOUS" and report.is_blocked) or (
        block_on == "HIGH_RISK" and report.score > 4.0
    )

    if should_block and not force:
        msg = f"Installation of [bold]{package}=={version}[/bold] was BLOCKED."
        if report.safe_version:
            msg += f"\n  Try: [bold green]pip install {package}=={report.safe_version}[/bold green]"
        console.print(f"\n[bold red]🚫 {msg}[/bold red]\n")
        sys.exit(1)

    # Proceed with install
    if should_block and force:
        console.print(
            "[bold yellow]⚠️  --force override: proceeding despite security risk[/bold yellow]"
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


@main.command()
@click.argument("lockfile", default="requirements.txt")
@click.option("--skip-dynamic", is_flag=True, help="Static analysis only (faster)")
@click.option("--workers", default=4, show_default=True, help="Parallel scan workers")
@click.option("--json-output", "-j", is_flag=True, help="Output as JSON")
@click.option(
    "--sarif-output", is_flag=True,
    help="Output as SARIF v2.1.0 (for GitHub Code Scanning)",
)
@click.option(
    "--fail-on",
    default="MALICIOUS",
    type=click.Choice(["HIGH_RISK", "MALICIOUS"]),
    help="Exit with error code if any package hits this verdict",
)
@click.option(
    "--offline", is_flag=True,
    help="No network calls. Requires --wheel-dir for audit.",
)
@click.option(
    "--wheel-dir", "wheel_dir",
    type=click.Path(exists=True, file_okay=False),
    help="Directory containing .whl files for offline scanning.",
)
def audit(
    lockfile: str,
    skip_dynamic: bool,
    workers: int,
    json_output: bool,
    sarif_output: bool,
    fail_on: str,
    offline: bool,
    wheel_dir: str | None,
):
    """
    Audit all packages in a lockfile / requirements file.

    \b
    Examples:
        chaincanary audit
        chaincanary audit requirements.txt
        chaincanary audit pyproject.toml --fail-on HIGH_RISK
        chaincanary audit requirements.txt --json-output | jq \
'.results[] | select(.verdict != "SAFE")'
    """
    from packaging.version import Version

    from chaincanary.downloader import get_all_versions
    from chaincanary.lockfile import detect_lockfile, parse_lockfile

    if offline and not wheel_dir:
        reporter.print_error(
            "--offline requires --wheel-dir <directory>. "
            "Provide a directory containing .whl files."
        )
        sys.exit(1)

    # Build wheel lookup table for offline mode
    wheel_lookup: dict[str, Path] = {}
    if wheel_dir:
        wd = Path(wheel_dir)
        for whl_file in wd.glob("*.whl"):
            # Wheel filename: {name}-{version}-{python}-{abi}-{platform}.whl
            # Last 3 parts are always: python, abi, platform
            # Everything before that is: name-version
            parts = whl_file.stem.split("-")
            if len(parts) >= 5:
                # Standard wheel: name-ver-py-abi-plat
                # Name may contain hyphens, so join everything except
                # version (second-to-last-3) and the 3 trailing tags
                name_ver = "-".join(parts[:-3])
                # Split name from version: version is the last segment
                nv_parts = name_ver.rsplit("-", 1)
                if len(nv_parts) == 2:
                    pkg_name = nv_parts[0].lower().replace("_", "-")
                    pkg_version = nv_parts[1]
                    wheel_lookup[f"{pkg_name}=={pkg_version}"] = whl_file

    # Use stderr for diagnostics when stdout is structured data
    structured = json_output or sarif_output
    out = err_console if structured else console

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
            out.print(f"[dim]Auto-detected: {lock_path}[/dim]")
        else:
            reporter.print_error(f"File not found: {lockfile}")
            sys.exit(1)

    specs = parse_lockfile(lock_path)
    if not specs:
        reporter.print_error(f"No packages found in {lock_path}")
        sys.exit(1)

    if not structured:
        out.print(
            f"\n[bold cyan]🔍 chaincanary audit[/bold cyan]"
            f" — {lock_path} ({len(specs)} packages)\n"
        )

    results = []
    engine = AnalysisEngine(
        skip_dynamic=skip_dynamic, offline=offline,
    )

    def scan_one(spec):
        # ── Git dependencies: flag immediately, don't scan PyPI ──────
        if spec.is_git_dep:
            return {
                "package": spec.name,
                "version": "git",
                "score": 5.0,
                "verdict": "HIGH_RISK",
                "safe_version": None,
                "findings": [
                    {
                        "rule_id": "GIT_DEPENDENCY",
                        "severity": "HIGH",
                        "title": (
                            f"Git dependency bypasses PyPI review: {spec.git_url or spec.name}"
                        ),
                    }
                ],
            }

        version = spec.version
        if not version and not offline:
            # Resolve latest
            try:
                versions = get_all_versions(spec.name)
                parsed = sorted(
                    [Version(v) for v in versions if not Version(v).is_prerelease],
                    reverse=True,
                )
                version = str(parsed[0]) if parsed else None
            except Exception:
                version = None

        if not version and offline:
            # In offline mode, try to find version from wheel_lookup
            for key in wheel_lookup:
                if key.startswith(spec.name.lower().replace("_", "-") + "=="):
                    version = key.split("==")[1]
                    break

        if not version:
            return {
                "package": spec.name,
                "version": "unknown",
                "score": 0,
                "verdict": "UNKNOWN",
                "findings": [],
            }

        # Look up local wheel if in offline mode
        local_whl = None
        if wheel_dir:
            pkg_norm = spec.name.lower().replace("_", "-")
            key = f"{pkg_norm}=={version}"
            local_whl = wheel_lookup.get(key)

        if offline and not local_whl:
            # Still run typosquatting check (no network needed)
            from chaincanary.safety_checks import check_typosquatting

            findings_list = []
            typo = check_typosquatting(spec.name)
            if typo:
                findings_list.append({
                    "rule_id": "TYPOSQUATTING",
                    "severity": "HIGH" if typo["likely_typosquat"] else "MEDIUM",
                    "title": (
                        f"Package name resembles '{typo['target']}' "
                        f"(edit distance: {typo['distance']})"
                    ),
                })
            findings_list.append({
                "rule_id": "OFFLINE_NO_WHEEL",
                "severity": "INFO",
                "title": (
                    f"No .whl found for {spec.name}=={version}"
                    " in wheel directory"
                ),
            })
            return {
                "package": spec.name,
                "version": version,
                "score": 0,
                "verdict": "UNKNOWN",
                "findings": findings_list,
            }

        report = engine.analyze(
            spec.name, version, local_wheel=local_whl,
        )
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
    if json_output or sarif_output or not console.is_terminal:
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
    elif sarif_output:
        from chaincanary.sarif import reports_to_sarif

        click.echo(json.dumps(reports_to_sarif(results), indent=2))
    else:
        _print_audit_table(results)

    # Exit code
    risky = [
        r
        for r in results
        if r["verdict"] in (["MALICIOUS"] if fail_on == "MALICIOUS" else ["MALICIOUS", "HIGH_RISK"])
    ]
    if risky:
        if not structured:
            out.print(
                f"[bold red]✗ {len(risky)} package(s) failed the audit."
                "[/bold red]\n"
            )
        sys.exit(1)
    else:
        if not structured:
            out.print(
                f"[bold green]✓ All {len(results)} packages passed audit."
                "[/bold green]\n"
            )


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
        chaincanary diff litellm 1.82.6 1.82.7

    This shows exactly what changed between versions — new files,
    new network behavior, new persistence mechanisms.
    """
    import tempfile
    from pathlib import Path

    from chaincanary.analyzer.differ import diff_from_static
    from chaincanary.analyzer.static import StaticAnalyzer
    from chaincanary.downloader import download_wheel

    console.print(
        f"\n[bold cyan]🔍 chaincanary diff[/bold cyan] — "
        f"[bold]{package}[/bold] "
        f"[dim]{version_a}[/dim] → [bold]{version_b}[/bold]\n"
    )

    static = StaticAnalyzer()

    with tempfile.TemporaryDirectory(prefix="chaincanary_diff_") as tmpdir:
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

    from rich import box
    from rich.table import Table

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
