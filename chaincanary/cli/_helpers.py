"""Shared helpers for chaincanary CLI commands."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.spinner import Spinner
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
    err_console.print(f"  [dim]\u2192 Resolving to latest: {latest}[/dim]")
    return latest


def _run_analysis(
    package: str,
    version: str,
    skip_dynamic: bool = False,
    verbose: bool = False,
    quiet: bool = False,  # suppress spinner (e.g., JSON mode or batch)
    local_wheel: str | None = None,
    offline: bool = False,
    timeout: int = 30,
    internal_names_set: set[str] | None = None,
    check_attestation: bool = True,
):
    """Run full analysis with live progress display."""
    if not quiet:
        reporter.print_scanning(package, version)

    engine = AnalysisEngine(
        skip_dynamic=skip_dynamic, verbose=verbose,
        offline=offline, timeout=timeout,
        internal_names=internal_names_set,
        check_attestation_flag=check_attestation,
    )
    local_path = Path(local_wheel) if local_wheel else None

    if quiet or not console.is_terminal:
        # JSON / piped output -- no spinner, no color pollution
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

            report = engine.analyze(
                package, version, on_progress=on_progress, local_wheel=local_path,
            )

    return report
