"""
cli.py — Entry point for VulnMind.

Command structure:
  vulnmind analyze <files> [--enrich] [--deep] [--report pdf] [--output path] [--format text|json]
  vulnmind config set-key <api-key>
  vulnmind config show
  vulnmind config clear
"""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel

from vulnmind import __version__
from vulnmind.banner import render as render_banner
from vulnmind.config import Config

console = Console()


def print_banner():
    """Print the VulnMind + Sombra-1 banner. Suppressed in JSON mode."""
    console.print(render_banner(use_color=True))


# ---------------------------------------------------------------------------
# Main CLI group
# ---------------------------------------------------------------------------

@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="VulnMind")
@click.pass_context
def cli(ctx):
    """
    VulnMind — Security scan analyzer.

    Parse and analyze output from nmap, nikto, and other security tools.
    Get structured findings, CVE matches, priority rankings, and reports.

    \b
    Quick start:
      nmap -oX scan.xml 192.168.1.0/24
      vulnmind analyze scan.xml
    """
    if ctx.invoked_subcommand is None:
        print_banner()
        console.print(ctx.get_help())


# ---------------------------------------------------------------------------
# analyze command
# ---------------------------------------------------------------------------

@cli.command()
@click.argument(
    "files",
    nargs=-1,
    required=True,
    type=click.Path(exists=True, readable=True, path_type=Path),
)
@click.option(
    "--report",
    type=click.Choice(["pdf"]),
    default=None,
    help="Generate a PDF report.",
)
@click.option(
    "--output",
    default="vulnmind_report.pdf",
    show_default=True,
    help="Output filename for the PDF report.",
)
@click.option(
    "--enrich",
    is_flag=True,
    default=False,
    help="AI analysis: plain-English explanations, exploit commands, Metasploit modules.",
)
@click.option(
    "--deep",
    is_flag=True,
    default=False,
    help="Look up each CVE in NVD for official CVSS scores + more evidence to AI.",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format. Use 'json' for machine-readable output.",
)
def analyze(files: tuple, report: str | None, output: str, enrich: bool, deep: bool, output_format: str):
    """
    Analyze one or more scanner output files.

    \b
    Supported formats:
      nmap -oX scan.xml    (recommended)
      nmap -oN scan.nmap   (text output)
      nikto -o scan.txt    (nikto output)

    \b
    Examples:
      vulnmind analyze scan.xml
      vulnmind analyze scan.xml nikto.txt
      vulnmind analyze scan.xml --enrich
      vulnmind analyze scan.xml --enrich --deep
      vulnmind analyze scan.xml --report pdf --output report.pdf
      vulnmind analyze scan.xml --format json > findings.json
    """
    if output_format == "text":
        print_banner()

    # Start update check in background — overlaps with parsing, costs nothing
    if output_format == "text":
        from vulnmind.updater import start_check
        start_check()

    cfg = Config.load()

    # Only check for API key if --enrich was requested
    if enrich and not cfg.groq_api_key:
        console.print(Panel(
            "No API key configured.\n\n"
            "Get a free key at [bold]console.groq.com[/bold] then run:\n\n"
            "  [bold]vulnmind config set-key <your-key>[/bold]",
            title="[bold red]Setup Required[/bold red]",
            border_style="red",
        ))
        sys.exit(1)

    from vulnmind.parsers import load_files
    from vulnmind.matcher import match_findings

    # --- Parse ---
    all_findings = []
    for file_path in files:
        try:
            findings = load_files([file_path])
            all_findings.extend(findings)
        except Exception as e:
            console.print(f"[red]Error parsing {file_path.name}:[/red] {e}")
            sys.exit(1)

    if not all_findings:
        if output_format == "json":
            import json as _json
            console.print(_json.dumps([]))
        else:
            console.print(Panel(
                "No findings were extracted from the provided file(s).\n\n"
                "This could mean:\n"
                "  - The scan found no open ports or vulnerabilities\n"
                "  - The file format wasn't recognised\n"
                "  - The scan was incomplete or empty",
                title="[yellow]No Findings[/yellow]",
                border_style="yellow",
            ))
        return

    # --- Knowledge base match (always runs, offline) ---
    findings = match_findings(all_findings)

    # --- NVD live CVE lookup (if --deep) ---
    if deep:
        findings = _nvd_enrich(findings, output_format)

    # --- AI enrich if requested ---
    if enrich:
        from vulnmind.ai import enrich_findings
        findings = enrich_findings(findings, cfg, deep=deep)

    # --- JSON output ---
    if output_format == "json":
        import json as _json
        import dataclasses
        # Bypass Rich console — it word-wraps long strings and corrupts JSON
        sys.stdout.write(_json.dumps(
            [dataclasses.asdict(f) for f in findings], indent=2, default=str
        ) + "\n")
        return

    # --- Display ---
    display_results(findings, enrich)

    # --- PDF ---
    if report == "pdf":
        from vulnmind.report import generate_pdf
        generate_pdf(findings, output)
        console.print(f"\n[green]Report saved:[/green] {output}")

    # --- Update notice (shown last, after everything else) ---
    if output_format == "text":
        from vulnmind.updater import get_notice
        notice = get_notice()
        if notice:
            console.print(notice)


# ---------------------------------------------------------------------------
# NVD enrichment helper
# ---------------------------------------------------------------------------

def _nvd_enrich(findings: list, output_format: str) -> list:
    """Run NVD CVE lookups with a progress bar (if text output)."""
    from vulnmind.nvd import enrich_with_nvd

    # Count total unique CVEs first
    unique_cves = set()
    for f in findings:
        for cve in (f.cve_ids or []):
            unique_cves.add(cve.upper())

    if not unique_cves:
        return findings

    if output_format == "json":
        # No progress bar in JSON mode
        return enrich_with_nvd(findings)

    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(
            f"Fetching CVE data from NVD ({len(unique_cves)} CVEs)...",
            total=len(unique_cves),
        )

        def _cb(current, total, cve_id):
            if cve_id:
                progress.update(task, completed=current, description=f"NVD: {cve_id}")
            else:
                progress.update(task, completed=total)

        return enrich_with_nvd(findings, progress_callback=_cb)


# ---------------------------------------------------------------------------
# config command group
# ---------------------------------------------------------------------------

@cli.group()
def config():
    """Manage VulnMind configuration."""
    pass


@config.command("set-key")
@click.argument("api_key")
def config_set_key(api_key: str):
    """Save your Groq API key for deep analysis.

    \b
    Get a free key at: console.groq.com
    Usage: vulnmind config set-key gsk_...
    """
    cfg = Config.load()
    cfg.set("groq_api_key", api_key)
    cfg.save()
    console.print(f"[green]API key saved.[/green] ({api_key[:8]}...)")


@config.command("clear")
def config_clear():
    """Remove all saved configuration (API key and preferences)."""
    cfg = Config.load()
    cfg._data.clear()
    cfg.save()
    console.print("[green]Configuration cleared.[/green]")


@config.command("show")
def config_show():
    """Show current configuration."""
    cfg = Config.load()
    display = cfg.display_dict()
    if not display:
        console.print("[dim]No configuration set.[/dim]")
        return
    for key, value in display.items():
        console.print(f"  [cyan]{key}[/cyan]: {value}")


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

def display_results(findings: list, enrich: bool):
    total    = len(findings)
    critical = sum(1 for f in findings if f.priority == "critical")
    high     = sum(1 for f in findings if f.priority == "high")
    medium   = sum(1 for f in findings if f.priority == "medium")
    low      = sum(1 for f in findings if f.priority == "low")
    unknown  = total - critical - high - medium - low

    mode_badge = "[green]ENRICH[/green]" if enrich else "[dim]BASIC[/dim]"
    header = (
        f"[bold]VulnMind[/bold] {mode_badge}  ·  "
        f"[red]{critical} critical[/red]  "
        f"[orange1]{high} high[/orange1]  "
        f"[yellow]{medium} medium[/yellow]  "
        f"[green]{low} low[/green]  "
        f"[dim]{unknown} unrated[/dim]  "
        f"[dim]({total} total)[/dim]"
    )
    console.print(Panel(header, border_style="blue", padding=(0, 1)))
    console.print()

    for finding in findings:
        display_finding_panel(finding)

    if not enrich:
        console.print(Panel(
            "Add [bold]--enrich[/bold] for AI explanations, exploit commands, and Metasploit modules.\n"
            "Add [bold]--report pdf[/bold] to export a PDF report.\n\n"
            "[dim]--enrich requires a free Groq API key: console.groq.com[/dim]",
            title="[bold dim]Tips[/bold dim]",
            border_style="dim",
            padding=(0, 2),
        ))


def display_finding_panel(finding):
    priority_colors = {
        "critical": "bold red",
        "high":     "orange1",
        "medium":   "yellow",
        "low":      "green",
    }
    priority = finding.priority or "unrated"
    color = priority_colors.get(priority, "dim")
    priority_badge = f"[{color}]{priority.upper()}[/{color}]"

    lines = []

    port_str    = f":{finding.port}" if finding.port else ""
    service_str = f"  [{finding.service}]" if finding.service else ""
    lines.append(f"[dim]Target:[/dim] [bold]{finding.host}{port_str}[/bold]{service_str}")

    if finding.cve_ids:
        lines.append(f"[dim]CVEs:[/dim]   [cyan]{', '.join(finding.cve_ids)}[/cyan]")

    if finding.cvss_score is not None:
        lines.append(f"[dim]CVSS:[/dim]   [bold]{finding.cvss_score:.1f}[/bold]")

    if finding.priority_reason:
        lines.append(f"[dim]Why {finding.priority or 'this priority'}:[/dim] [dim italic]{finding.priority_reason}[/dim italic]")

    lines.append("")

    if finding.ai_explanation:
        lines.append(finding.ai_explanation)
    else:
        lines.append(f"[dim]{finding.description}[/dim]")

    if finding.remediation:
        lines.append("")
        lines.append("[bold]Remediation:[/bold]")
        lines.append(f"  [blue]{finding.remediation}[/blue]")

    if finding.suggested_commands:
        lines.append("")
        lines.append("[bold]Next steps:[/bold]")
        for cmd in finding.suggested_commands:
            lines.append(f"  [green]$[/green] [white]{cmd}[/white]")

    if finding.metasploit_modules:
        lines.append("")
        lines.append("[bold]Metasploit:[/bold]")
        for mod in finding.metasploit_modules:
            lines.append(f"  [red]msf[/red] [dim]>[/dim] use {mod}")

    if finding.false_positive_likelihood in ("medium", "high"):
        lines.append("")
        fp_color = "yellow" if finding.false_positive_likelihood == "medium" else "orange1"
        lines.append(f"[{fp_color}]! False positive likelihood: {finding.false_positive_likelihood}[/{fp_color}]")
        if finding.false_positive_reason:
            lines.append(f"[dim]  {finding.false_positive_reason}[/dim]")

    console.print(Panel(
        "\n".join(lines),
        title=f"{priority_badge}  [bold]{finding.title}[/bold]",
        border_style=color,
        padding=(1, 2),
    ))
    console.print()
