"""diff command -- compare two versions of a package."""

from __future__ import annotations

import json
import sys

import click

from chaincanary import reporter
from chaincanary.cli._helpers import console
from chaincanary.cli._main import main


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

    This shows exactly what changed between versions -- new files,
    new network behavior, new persistence mechanisms.
    """
    import tempfile
    from pathlib import Path

    from rich import box
    from rich.table import Table

    from chaincanary.analyzer.differ import diff_from_static
    from chaincanary.analyzer.static import StaticAnalyzer
    from chaincanary.downloader import download_wheel

    console.print(
        f"\n[bold cyan]\U0001f50d chaincanary diff[/bold cyan] \u2014 "
        f"[bold]{package}[/bold] "
        f"[dim]{version_a}[/dim] \u2192 [bold]{version_b}[/bold]\n"
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
        console.print("[green]\u2713 No file-level changes between versions.[/green]\n")
        sys.exit(0)

    table = Table(box=box.ROUNDED, title=f"File changes: {package} {version_a} \u2192 {version_b}")
    table.add_column("Change", width=8)
    table.add_column("File", ratio=1)
    table.add_column("Risk", width=12)

    for f in new_pth:
        table.add_row("[bold red]ADDED[/bold red]", f, "[bold red]\u26a0 .pth file[/bold red]")
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
            f"\n[bold red]\u2620\ufe0f  CRITICAL: New .pth file(s) detected![/bold red]\n"
            f"  {new_pth}\n"
            f"  This is the exact attack vector used in the LiteLLM 1.82.7 supply chain attack.\n"
        )
        sys.exit(1)

    console.print()
    sys.exit(0)
