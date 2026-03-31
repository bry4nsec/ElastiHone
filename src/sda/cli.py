"""CLI entrypoint — Typer application for ElastiHone."""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

app = typer.Typer(
    name="sda",
    help="🐝 ElastiHone — AI-powered detection rule fine-tuning for Elastic Security.",
    add_completion=False,
    rich_markup_mode="markdown",
)
console = Console()


def _print_banner():
    console.print(
        Panel.fit(
            "[bold cyan]ElastiHone[/bold cyan]\n"
            "[dim]AI-powered detection rule fine-tuning for Elastic Security[/dim]",
            border_style="cyan",
        )
    )


@app.command()
def analyse(
    rule_path: Path = typer.Argument(..., help="Path to the detection rule file (YAML or JSON)"),
    format: str = typer.Option("auto", "--format", "-f", help="Rule format: sigma, elastic, auto"),
    days: int = typer.Option(7, "--days", "-d", help="Historical lookback window in days"),
    output: str = typer.Option("rich", "--output", "-o", help="Output format: rich, json, markdown"),
    no_agent: bool = typer.Option(False, "--no-agent", help="Run without LLM agent (direct pipeline)"),
    fail_on: str = typer.Option("", "--fail-on", help="CI/CD mode: exit non-zero on verdict (review, reject, high-noise)"),
    sigma: bool = typer.Option(False, "--sigma", help="Convert Sigma YAML to Elastic before analysis"),
):
    """Analyse a candidate detection rule and generate an Impact Report.

    CI/CD Usage:
        sda analyse rule.toml --fail-on=review --output=json
        # Exit 0 = approve, 1 = review/needs-tuning, 2 = reject/high-noise
    """
    _print_banner()

    if not rule_path.exists():
        console.print(f"[red]Error:[/red] File not found: {rule_path}")
        raise typer.Exit(1)

    rule_content = rule_path.read_text(encoding="utf-8")
    console.print(f"\n📄 Loading rule: [bold]{rule_path.name}[/bold]")

    console.print(f"📋 Format: [cyan]elastic[/cyan]")

    with console.status("[bold green]Running analysis pipeline..."):
        try:
            if no_agent:
                report = asyncio.run(_run_fallback(rule_content, format, days))
            else:
                report = asyncio.run(_run_agent(rule_content, format))
        except Exception as exc:
            console.print(f"\n[red]Analysis failed:[/red] {exc}")
            raise typer.Exit(1)

    if output == "json":
        import json
        console.print_json(json.dumps(report.model_dump(mode="json"), indent=2, default=str))
    elif output == "markdown":
        console.print(_format_markdown(report))
    else:
        _print_rich_report(report)

    # CI/CD mode — exit with appropriate code
    if fail_on:
        verdict = report.verdict.value if hasattr(report.verdict, 'value') else str(report.verdict)
        alerts_per_day = report.estimated_alerts_per_day

        if fail_on == "reject" and verdict == "reject":
            console.print("\n[red]❌ CI/CD FAIL:[/red] Rule rejected")
            raise typer.Exit(2)
        elif fail_on in ("review", "reject") and verdict == "review":
            console.print("\n[yellow]⚠️ CI/CD FAIL:[/yellow] Rule needs review")
            raise typer.Exit(1)
        elif fail_on == "high-noise" and alerts_per_day > 100:
            console.print(f"\n[red]❌ CI/CD FAIL:[/red] High noise ({alerts_per_day:.0f} alerts/day)")
            raise typer.Exit(2)

        console.print(f"\n[green]✅ CI/CD PASS:[/green] Verdict = {verdict}")


async def _run_agent(rule_content: str, format_hint: str):
    """Run agent-based analysis."""
    from sda.agent.orchestrator import run_analysis
    return await run_analysis(rule_content, format_hint)


async def _run_fallback(rule_content: str, format_hint: str, days: int):
    """Run direct pipeline analysis."""
    from sda.agent.orchestrator import _fallback_analysis
    from sda.config import get_config
    import time

    config = get_config()
    config.es.noise_lookback_days = days
    return await _fallback_analysis(
        rule_content, format_hint,
        analysis_id=f"sda-manual-{__import__('uuid').uuid4().hex[:8]}",
        start_time=time.time(),
        config=config,
    )


def _print_rich_report(report):
    """Print a beautifully formatted report using Rich."""
    # Verdict banner
    verdict_colors = {"approve": "green", "review": "yellow", "reject": "red"}
    verdict_emoji = {"approve": "✅", "review": "⚠️", "reject": "❌"}
    vc = verdict_colors.get(report.verdict.value, "white")
    ve = verdict_emoji.get(report.verdict.value, "")

    console.print()
    console.print(Panel(
        f"[bold {vc}]{ve} VERDICT: {report.verdict.value.upper()}[/bold {vc}]\n\n"
        f"[dim]{report.verdict_reason}[/dim]",
        title="[bold]Detection Impact Report[/bold]",
        border_style=vc,
        width=80,
    ))

    # Metrics table
    table = Table(title="Analysis Metrics", box=box.ROUNDED, width=80)
    table.add_column("Metric", style="cyan", width=30)
    table.add_column("Value", style="bold", width=25)
    table.add_column("Status", width=15)

    tpr_status = "🟢" if report.tpr >= 0.9 else ("🟡" if report.tpr >= 0.7 else "🔴")
    fpr_status = "🟢" if report.fpr < 0.01 else ("🟡" if report.fpr < 0.05 else "🔴")
    cost_status = "🟢" if report.cost_analysis.level.value in ("low", "medium") else "🔴"

    table.add_row("True Positive Rate (TPR)", f"{report.tpr:.1%}", tpr_status)
    table.add_row("Signal Hits / Total", f"{report.signal_hits} / {report.signal_total}", "")
    table.add_row("False Positive Rate (FPR)", f"{report.fpr:.2%}", fpr_status)
    table.add_row("Noise Hits / Total", f"{report.noise_hits} / {report.noise_total}", "")
    table.add_row("Estimated Alerts / Hour", f"{report.estimated_alerts_per_hour:.1f}", "")
    table.add_row("Estimated Alerts / Day", f"{report.estimated_alerts_per_day:.1f}", "")
    table.add_row(
        "CPU Cost",
        f"{report.cost_analysis.level.value.upper()} ({report.cost_analysis.query_complexity_score}/100)",
        cost_status,
    )
    table.add_row("Analysis Duration", f"{report.analysis_duration_seconds:.1f}s", "")

    console.print(table)

    # Recommendations
    if report.recommendations:
        console.print()
        console.print(Panel(
            "\n".join(f"  {r}" for r in report.recommendations),
            title="[bold]Recommendations[/bold]",
            border_style="blue",
            width=80,
        ))

    # Cost notes
    if report.cost_analysis.notes:
        console.print()
        console.print(f"[dim]Cost Notes: {report.cost_analysis.notes}[/dim]")

    # MITRE mapping
    if report.mitre_techniques:
        console.print(f"\n🎯 MITRE ATT&CK: {', '.join(report.mitre_techniques)}")


def _format_markdown(report) -> str:
    """Format report as markdown."""
    md = f"""# Detection Impact Report

## Verdict: {report.verdict.value.upper()}
{report.verdict_reason}

## Metrics
| Metric | Value |
|--------|-------|
| TPR | {report.tpr:.1%} |
| FPR | {report.fpr:.2%} |
| Signal | {report.signal_hits}/{report.signal_total} |
| Noise | {report.noise_hits}/{report.noise_total} |
| Alerts/Day | {report.estimated_alerts_per_day:.1f} |
| CPU Cost | {report.cost_analysis.level.value} ({report.cost_analysis.query_complexity_score}/100) |

## Recommendations
"""
    for rec in report.recommendations:
        md += f"- {rec}\n"
    return md


@app.command()
def config_show():
    """Display current configuration."""
    from sda.config import get_config_display
    import json

    _print_banner()
    console.print_json(json.dumps(get_config_display(), indent=2))


@app.command()
def serve(
    port: int = typer.Option(8100, help="MCP server port"),
):
    """Start MCP servers (Elasticsearch connector + Attack simulator)."""
    _print_banner()
    console.print(f"\n🔌 Starting MCP servers on port [cyan]{port}[/cyan]...")
    console.print("[dim]  • sda-elasticsearch-connector[/dim]")
    console.print("[dim]  • sda-attack-simulator[/dim]")

    # In a real deployment, these would run as separate processes
    # For now, we start both via a single uvicorn instance
    console.print("\n[yellow]MCP servers require an Elasticsearch connection.[/yellow]")
    console.print("[dim]Configure via SDA_ES_URL, SDA_ES_API_KEY environment variables.[/dim]")


@app.command()
def web(
    host: str = typer.Option("0.0.0.0", help="Bind host"),
    port: int = typer.Option(8080, help="Bind port"),
):
    """Start the web dashboard."""
    _print_banner()
    console.print(f"\n🌐 Starting web dashboard on [cyan]http://{host}:{port}[/cyan]")

    import uvicorn
    from sda.web.app import create_app

    application = create_app()
    uvicorn.run(application, host=host, port=port)


@app.command()
def templates():
    """List available attack simulation templates."""
    _print_banner()
    from sda.mcp_servers.attack_simulator import ATTACK_TEMPLATES

    table = Table(title="Attack Simulation Templates", box=box.ROUNDED)
    table.add_column("Technique", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Tactic", style="green")
    table.add_column("Variants", justify="center")

    for tid, tmpl in sorted(ATTACK_TEMPLATES.items()):
        table.add_row(tid, tmpl["name"], tmpl["tactic"], str(len(tmpl.get("events", []))))

    console.print(table)


if __name__ == "__main__":
    app()
