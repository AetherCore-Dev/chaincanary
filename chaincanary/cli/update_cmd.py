"""update command -- refresh known-malicious hash database."""

from __future__ import annotations

import click

from chaincanary.cli._helpers import console
from chaincanary.cli._main import main


@main.command()
@click.option(
    "--feed-url", default=None,
    help="Custom hash feed URL (default: GitHub raw).",
)
def update(feed_url: str | None):
    """
    Update the known-malicious hash database from the remote feed.

    \b
    Examples:
        chaincanary update
        chaincanary update --feed-url https://example.com/hashes.json
    """
    from chaincanary.hashfeed import DEFAULT_FEED_URL, HashFeedManager

    url = feed_url or DEFAULT_FEED_URL
    console.print(
        "[bold cyan]\U0001f504 chaincanary update[/bold cyan]"
        " \u2014 refreshing hash database\n"
    )
    console.print(f"[dim]Feed: {url}[/dim]")

    mgr = HashFeedManager(feed_url=url)
    hashes = mgr.get_hashes(force_refresh=True)

    if hashes:
        console.print(
            f"[bold green]\u2713 Updated: {len(hashes)} "
            f"known-malicious hashes loaded.[/bold green]\n"
        )
    else:
        console.print(
            "[bold yellow]\u26a0 No hashes retrieved. "
            "Check your network or feed URL.[/bold yellow]\n"
        )
