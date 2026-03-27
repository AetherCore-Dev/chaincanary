"""Click group definition for chaincanary CLI."""

from __future__ import annotations

import click


@click.group()
@click.version_option(prog_name="chaincanary")
def main():
    """
    \b
    chaincanary -- pip installation security sandbox
    Detects supply chain attacks before they compromise your system.

    \b
    Quick start:
        chaincanary check litellm==1.82.7
        chaincanary install requests
    """
    pass
