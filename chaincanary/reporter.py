"""
Rich terminal reporter — beautiful output for chaincanary results.
"""
from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from chaincanary.models import RiskReport, Finding, Severity

console = Console()

# Color map
SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

VERDICT_COLORS = {
    "SAFE": "bold green",
    "LOW_RISK": "yellow",
    "HIGH_RISK": "bold orange3",
    "MALICIOUS": "bold red",
}

VERDICT_ICONS = {
    "SAFE": "✅",
    "LOW_RISK": "⚠️ ",
    "HIGH_RISK": "🚨",
    "MALICIOUS": "☠️ ",
}


def print_scanning(package: str, version: str) -> None:
    console.print(
        f"\n[bold cyan]🔍 chaincanary[/bold cyan] — Analyzing "
        f"[bold]{package}=={version}[/bold] ...\n"
    )


def print_static_start() -> None:
    console.print("  [dim]→ Running static analysis...[/dim]")


def print_dynamic_start() -> None:
    console.print("  [dim]→ Running sandbox analysis (Docker)...[/dim]")


def print_report(report: RiskReport) -> None:
    """Print the full risk report to terminal."""
    _print_findings_table(report)
    _print_verdict_panel(report)

    if report.behavior_diff:
        _print_diff(report.behavior_diff)


def _print_findings_table(report: RiskReport) -> None:
    if not report.findings:
        return

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold",
        title=f"Findings for [bold]{report.package}=={report.version}[/bold]",
        title_style="bold white",
        expand=True,
    )
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Rule", width=28)
    table.add_column("Title", ratio=1)
    table.add_column("Source", width=8)

    for finding in sorted(report.findings, key=lambda f: list(Severity).index(f.severity)):
        color = SEVERITY_COLORS[finding.severity]
        table.add_row(
            f"[{color}]{finding.severity.value}[/{color}]",
            f"[dim]{finding.rule_id}[/dim]",
            finding.title,
            f"[dim]{finding.source}[/dim]",
        )

    console.print()
    console.print(table)


def _print_verdict_panel(report: RiskReport) -> None:
    icon = VERDICT_ICONS.get(report.verdict, "❓")
    color = VERDICT_COLORS.get(report.verdict, "white")

    lines = [
        f"[{color}]{icon}  {report.verdict}[/{color}]   "
        f"Risk Score: [{color}]{report.score:.1f} / 10[/{color}]",
        "",
    ]

    if report.findings:
        critical = [f for f in report.findings if f.severity == Severity.CRITICAL]
        high = [f for f in report.findings if f.severity == Severity.HIGH]
        medium = [f for f in report.findings if f.severity == Severity.MEDIUM]

        if critical:
            lines.append(f"  [bold red]● {len(critical)} CRITICAL finding(s)[/bold red]")
        if high:
            lines.append(f"  [red]● {len(high)} HIGH finding(s)[/red]")
        if medium:
            lines.append(f"  [yellow]● {len(medium)} MEDIUM finding(s)[/yellow]")

    if report.safe_version and report.verdict in ("HIGH_RISK", "MALICIOUS"):
        lines.append("")
        lines.append(
            f"  [green]💡 Safe version available:[/green] "
            f"[bold green]{report.package}=={report.safe_version}[/bold green]"
        )

    if report.is_blocked:
        lines.append("")
        lines.append(
            f"  [bold red]🚫 Installation BLOCKED.[/bold red] "
            f"Use [bold]--force[/bold] to override."
        )
    elif report.should_warn:
        lines.append("")
        lines.append(
            f"  [yellow]⚠️  Proceeding with caution. Use [bold]--block[/bold] to enforce blocking.[/yellow]"
        )

    panel_content = "\n".join(lines)
    border_color = VERDICT_COLORS.get(report.verdict, "white").replace("bold ", "")

    console.print()
    console.print(Panel(
        panel_content,
        title=f"[bold]{report.package}=={report.version}[/bold]",
        border_style=border_color,
        padding=(1, 2),
    ))
    console.print()


def _print_diff(diff: dict) -> None:
    """Print behavioral differences from previous version."""
    if not any(diff.values()):
        return

    console.print("[bold yellow]⚡ New behaviors vs previous version:[/bold yellow]")

    new_network = diff.get("new_network_calls", [])
    new_writes = diff.get("new_file_writes", [])
    new_procs = diff.get("new_subprocesses", [])
    new_pth = diff.get("new_pth_files", [])

    if new_pth:
        for item in new_pth:
            console.print(f"  [red]+ .pth file (NEW):[/red] {item}")
    if new_network:
        for item in new_network[:3]:
            console.print(f"  [red]+ network call (NEW):[/red] {item[:80]}")
    if new_writes:
        for item in new_writes[:3]:
            console.print(f"  [yellow]+ file write (NEW):[/yellow] {item[:80]}")
    if new_procs:
        for item in new_procs[:3]:
            console.print(f"  [yellow]+ subprocess (NEW):[/yellow] {item[:80]}")

    console.print()


def print_detail(finding: Finding) -> None:
    """Print detailed finding info including evidence."""
    color = SEVERITY_COLORS[finding.severity]
    console.print(f"\n[{color}][{finding.severity.value}][/{color}] {finding.title}")
    if finding.evidence:
        console.print(Panel(
            finding.evidence,
            title="Evidence",
            border_style="dim",
            padding=(0, 1),
        ))


def print_error(msg: str) -> None:
    console.print(f"\n[bold red]Error:[/bold red] {msg}\n")


def print_success(msg: str) -> None:
    console.print(f"\n[bold green]✓[/bold green] {msg}\n")
