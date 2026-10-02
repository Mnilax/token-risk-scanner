"""CLI interface for the token risk scanner."""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from scanner.analyze import analyze_token_sync
from scanner.models import RiskReport, Severity

app = typer.Typer(
    name="scanner",
    help="Token risk scanner — honeypot, mint authority, LP lock, holder concentration, tax analysis.",
    no_args_is_help=True,
)
console = Console()

@app.callback()
def commands():
    """Inspect token risk signals from public providers."""

SEVERITY_COLORS = {
    Severity.RED: "red",
    Severity.YELLOW: "yellow",
    Severity.GREEN: "green",
}

SEVERITY_ICONS = {
    Severity.RED: "🔴",
    Severity.YELLOW: "🟡",
    Severity.GREEN: "🟢",
}


def _render_report(report: RiskReport) -> None:
    """Render a risk report to the terminal."""
    token = report.token

    # Header
    name = token.name or "Unknown"
    symbol = token.symbol or "?"
    console.print()
    console.print(
        Panel(
            f"[bold]{name}[/bold] ({symbol})\n"
            f"Chain: {token.chain}  |  Address: {token.address}\n"
            f"Sources: {', '.join(report.data_sources) or 'none'}",
            title="Token Risk Report",
            border_style="blue",
        )
    )

    # Risk score
    if report.verdict.startswith(("UNKNOWN", "INCOMPLETE")):
        score_color = "yellow"
    elif report.risk_score >= 60:
        score_color = "red"
    elif report.risk_score >= 30:
        score_color = "yellow"
    else:
        score_color = "green"

    console.print(
        f"\n  Risk Score: [{score_color} bold]{report.risk_score}/100[/{score_color} bold]"
        f"  —  [{score_color}]{report.verdict}[/{score_color}]"
    )
    for error in report.data_errors:
        console.print(f"Source unavailable: {error}", markup=False, style="yellow")

    # Flags table
    if report.flags:
        console.print()
        table = Table(show_header=True, header_style="bold", box=None, padding=(0, 2))
        table.add_column("", width=2)
        table.add_column("Check", min_width=30)
        table.add_column("Detail", max_width=60)

        for flag in report.flags:
            color = SEVERITY_COLORS[flag.severity]
            icon = SEVERITY_ICONS[flag.severity]
            table.add_row(
                icon,
                f"[{color}]{flag.label}[/{color}]",
                f"[dim]{flag.detail}[/dim]",
            )

        console.print(table)

    # Extra info
    if token.holder_count:
        console.print(f"\n  Holders: {token.holder_count:,}")
    if token.total_supply:
        console.print(f"  Total supply: {token.total_supply}")

    console.print()


@app.command()
def scan(
    chain: str = typer.Argument(..., help="Chain: ethereum, bsc, polygon, arbitrum, base, solana, or chain ID"),
    address: str = typer.Argument(..., help="Token contract address"),
) -> None:
    """Scan a token for risks."""
    console.print(f"[dim]Scanning {address} on {chain}...[/dim]")

    try:
        report = analyze_token_sync(chain, address)
        _render_report(report)
    except Exception as e:  # noqa: BLE001 - CLI boundary reports provider failures.
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
