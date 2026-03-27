"""audit command -- scan all packages in a lockfile."""

from __future__ import annotations

import concurrent.futures
import json
import sys
from pathlib import Path

import click
from rich import box
from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn
from rich.table import Table

from chaincanary import reporter
from chaincanary.cli._helpers import console, err_console
from chaincanary.cli._main import main
from chaincanary.engine import AnalysisEngine


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
@click.option(
    "--timeout", type=click.IntRange(min=1, max=300),
    default=30, show_default=True,
    help="Per-request timeout in seconds (1\u2013300).",
)
@click.option(
    "--skip", "skip_packages", default="",
    help=(
        "Comma-separated package names to skip "
        "(e.g., --skip torch,tensorflow)."
    ),
)
@click.option(
    "--internal-names", default="",
    help=(
        "Comma-separated internal package names for "
        "dependency confusion detection."
    ),
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
    timeout: int,
    skip_packages: str,
    internal_names: str,
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
        err_console.print(
            f"[yellow]Warning:[/yellow] --workers {workers} capped to 16 to avoid PyPI rate-limits."
        )

    lock_path = Path(lockfile)
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

    # -- Apply --skip filter -----------------------------------------------
    skip_set = {
        s.strip().lower()
        for s in skip_packages.split(",")
        if s.strip()
    }
    skipped_names: list[str] = []
    if skip_set:
        filtered = []
        for spec in specs:
            if spec.name.lower() in skip_set:
                skipped_names.append(spec.name)
            else:
                filtered.append(spec)
        specs = filtered
        if not structured and skipped_names:
            out.print(
                f"[dim]Skipped {len(skipped_names)} package(s): "
                f"{', '.join(skipped_names)}[/dim]"
            )

    if not structured:
        out.print(
            f"\n[bold cyan]\U0001f50d chaincanary audit[/bold cyan]"
            f" \u2014 {lock_path} ({len(specs)} packages)\n"
        )

    # Parse internal names for dependency confusion detection
    int_names_set = {
        s.strip().lower()
        for s in internal_names.split(",")
        if s.strip()
    } if internal_names else None

    results: list[dict] = []
    engine = AnalysisEngine(
        skip_dynamic=skip_dynamic, offline=offline,
        timeout=timeout, internal_names=int_names_set,
    )

    def scan_one(spec):
        # -- Git dependencies: flag immediately, don't scan PyPI -----------
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
            TextColumn("[dim]{task.fields[current]}[/dim]"),
            console=console,
        ) as progress:
            task = progress.add_task(
                "Scanning packages...", total=len(specs), current="",
            )
            with concurrent.futures.ThreadPoolExecutor(max_workers=safe_workers) as ex:
                futures = {ex.submit(scan_one, s): s for s in specs}
                for fut in concurrent.futures.as_completed(futures):
                    result = fut.result()
                    results.append(result)
                    progress.update(
                        task,
                        advance=1,
                        current=result["package"],
                    )
                    if result["verdict"] in ("MALICIOUS", "HIGH_RISK"):
                        progress.print(
                            f"  [red]\u26a0  {result['package']}=={result['version']} "
                            f"\u2014 {result['verdict']}[/red]"
                        )

    # Sort by risk score descending
    results.sort(key=lambda r: r["score"], reverse=True)

    if json_output:
        output_data: dict = {
            "lockfile": str(lock_path),
            "results": results,
        }
        if skipped_names:
            output_data["skipped"] = skipped_names
        click.echo(json.dumps(output_data, indent=2))
    elif sarif_output:
        from chaincanary.sarif import reports_to_sarif

        click.echo(json.dumps(reports_to_sarif(results), indent=2))
    else:
        _print_audit_table(results)

    # Exit code
    risky = [
        r
        for r in results
        if r["verdict"] in (
            ["MALICIOUS"] if fail_on == "MALICIOUS" else ["MALICIOUS", "HIGH_RISK"]
        )
    ]
    if risky:
        if not structured:
            out.print(
                f"[bold red]\u2717 {len(risky)} package(s) failed the audit."
                "[/bold red]\n"
            )
        sys.exit(1)
    else:
        if not structured:
            out.print(
                f"[bold green]\u2713 All {len(results)} packages passed audit."
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
        top = r["findings"][0]["title"][:45] if r["findings"] else "\u2014"
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
