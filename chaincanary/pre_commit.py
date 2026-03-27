"""
Pre-commit hook integration for chaincanary.

Scans lockfiles for supply-chain attacks during git pre-commit.
Designed for use with https://pre-commit.com/.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import click

from chaincanary.engine import AnalysisEngine
from chaincanary.lockfile import parse_lockfile

# Lockfile patterns that this hook supports
_LOCKFILE_RE = re.compile(r"(requirements.*\.txt|pyproject\.toml|Pipfile\.lock)$", re.IGNORECASE)

_VERDICT_LEVELS = ("SAFE", "LOW_RISK", "HIGH_RISK", "MALICIOUS")


def _verdict_at_or_above(verdict: str, threshold: str) -> bool:
    """Return True if *verdict* meets or exceeds *threshold*."""
    try:
        return _VERDICT_LEVELS.index(verdict) >= _VERDICT_LEVELS.index(threshold)
    except ValueError:
        return False


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.argument("filenames", nargs=-1, type=click.Path(exists=True))
@click.option(
    "--fail-on",
    type=click.Choice(["MALICIOUS", "HIGH_RISK"], case_sensitive=False),
    default="MALICIOUS",
    show_default=True,
    help="Minimum verdict that causes a non-zero exit.",
)
@click.option(
    "--timeout",
    type=int,
    default=30,
    show_default=True,
    help="HTTP timeout in seconds for PyPI downloads.",
)
@click.option(
    "--skip",
    multiple=True,
    help="Package names to skip (can be repeated).",
)
def main(
    filenames: tuple[str, ...],
    fail_on: str,
    timeout: int,
    skip: tuple[str, ...],
) -> None:
    """Chaincanary pre-commit hook — scan lockfiles for supply-chain attacks."""
    fail_on_upper = fail_on.upper()
    skip_set = {s.lower() for s in skip}

    # Filter to supported lockfile types
    lockfiles = [Path(f) for f in filenames if _LOCKFILE_RE.search(Path(f).name)]
    if not lockfiles:
        sys.exit(0)

    engine = AnalysisEngine(skip_dynamic=True, timeout=timeout)

    blocked: list[str] = []

    for lockfile in lockfiles:
        specs = parse_lockfile(lockfile)
        for spec in specs:
            if spec.name.lower() in skip_set:
                continue
            if spec.is_git_dep:
                continue
            version = spec.version or "latest"
            report = engine.analyze(spec.name, version)
            if _verdict_at_or_above(report.verdict, fail_on_upper):
                blocked.append(
                    f"  {spec.name}=={version} ({report.verdict}, "
                    f"score={report.score:.1f}) [{lockfile.name}]"
                )

    if blocked:
        click.echo("chaincanary: supply-chain risk detected!", err=True)
        for line in blocked:
            click.echo(line, err=True)
        sys.exit(1)

    sys.exit(0)
