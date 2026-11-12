"""
cli.py — Entry point for VulnMind.

Command structure:
  vulnmind analyze <files> [--enrich] [--deep] [--report pdf] [--output path] [--format text|json]
  vulnmind scan <target>   [-p ports] [--nmap-args "..."] [--enrich] [--deep] [--report pdf] [--output path] [--format text|json]
  vulnmind update [--check-only]
  vulnmind config set-key <api-key>
  vulnmind config set-update-checks <on|off>
  vulnmind config show
  vulnmind config clear
"""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.markup import escape

from vulnmind import __version__
from vulnmind.banner import render as render_banner
from vulnmind.config import Config
from vulnmind.parsers.base import format_target

console = Console()


def print_banner():
    """Print the VulnMind + Sombra-1 banner. Suppressed in JSON mode."""
    console.print(render_banner(use_color=True))


def _print_error(message: str, output_format: str) -> None:
    """Keep machine-readable stdout clean while retaining useful diagnostics."""
    if output_format == "json":
        click.echo(message, err=True)
    else:
        console.print(message, markup=False)


# ---------------------------------------------------------------------------
# Main CLI group
# ---------------------------------------------------------------------------

@click.group(invoke_without_command=True)
@click.version_option(version=__version__, prog_name="VulnMind")
@click.pass_context
def cli(ctx):
    """
    VulnMind — Security scan analyzer.

    Parse and analyze output from nmap, Nuclei, nikto, and other security tools.
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
# Cache diagnostics (read-only, offline)
# ---------------------------------------------------------------------------

@cli.group()
def cache():
    """Inspect local intelligence caches without making network requests."""


@cache.command("status")
@click.option("--format", "output_format", type=click.Choice(["text", "json"]), default="text")
def cache_status_command(output_format):
    """Show cache freshness, corruption, and failed release checks."""
    import json
    from vulnmind.diagnostics import cache_status
    result = cache_status()
    if output_format == "json":
        click.echo(json.dumps(result, indent=2))
    else:
        from rich.table import Table
        table = Table(title="VulnMind cache health")
        for column in ("Source", "Status", "Entries", "Path"):
            table.add_column(column)
        for row in result["caches"]:
            table.add_row(row["source"], row["status"], str(row["entries"]), escape(row["path"]))
        console.print(table)
        if result["truncated"]:
            click.echo("Showing the first 1000 NVD cache files.")


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
    help="Refresh NVD, CISA KEV, and ExploitDB intelligence for associated CVEs.",
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
      nuclei -jsonl -o nuclei.jsonl
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
    _run_pipeline(
        file_paths=list(files),
        report=report,
        output=output,
        enrich=enrich,
        deep=deep,
        output_format=output_format,
        show_banner=True,
    )


# ---------------------------------------------------------------------------
# scan command — run nmap + analyze in one step (v0.4.0)
# ---------------------------------------------------------------------------

@cli.command()
@click.argument("target")
@click.option(
    "-p", "--ports",
    default=None,
    help="Port specification passed to nmap (e.g. '22,80,443' or '1-65535'). Disables --top-ports.",
)
@click.option(
    "--nmap-args",
    "nmap_args",
    default="",
    help='Extra flags forwarded to nmap, shell-quoted (e.g. --nmap-args "-T4 -Pn").',
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
    help="Refresh NVD, CISA KEV, and ExploitDB intelligence for associated CVEs.",
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
    help="Output format. Use 'json' for machine-readable output.",
)
def scan(
    target: str,
    ports: str | None,
    nmap_args: str,
    report: str | None,
    output: str,
    enrich: bool,
    deep: bool,
    output_format: str,
):
    """
    Scan a live target with nmap and analyze the results in one step.

    \b
    Target can be an IP, hostname, or CIDR range:
      vulnmind scan 192.168.1.1
      vulnmind scan target.local -p 22,80,443
      vulnmind scan 10.0.0.0/24 --deep
      vulnmind scan scanme.nmap.org --enrich --nmap-args "-T4 -Pn"

    \b
    Defaults: nmap -sV -sC --top-ports 1000
    (version detection, default NSE scripts, top 1000 ports).
    Use -p/--ports to override the port range, or --nmap-args to pass
    arbitrary extra flags through to nmap.

    Requires the nmap binary on PATH.
    """
    from vulnmind.scanner import run_nmap, nmap_available, ScannerError

    if output_format == "text":
        print_banner()
        console.print(Panel(
            "[bold]Only scan systems you own or have written authorisation to test.[/bold]\n"
            "[dim]Unauthorised scanning may violate computer-misuse laws in your jurisdiction.[/dim]",
            title="[yellow]! Authorisation notice[/yellow]",
            border_style="yellow",
            padding=(0, 2),
        ))

    if not nmap_available():
        _print_error(
            (
                "nmap binary not found on PATH. Install with: sudo pacman -S "
                "nmap (Arch) or sudo apt install nmap (Debian/Kali)."
            ),
            output_format,
        )
        sys.exit(1)

    # Run nmap — stderr streams to terminal in text mode so user sees progress.
    # In JSON mode we silence nmap so the JSON output stays clean.
    quiet = output_format == "json"
    if output_format == "text":
        console.print(f"[dim]Running nmap against[/dim] [bold]{target}[/bold]...")

    try:
        xml_path = run_nmap(
            target=target,
            ports=ports,
            extra_args_str=nmap_args,
            quiet=quiet,
        )
    except ScannerError as e:
        _print_error(str(e), output_format)
        sys.exit(1)
    except KeyboardInterrupt:
        _print_error("Scan interrupted.", output_format)
        sys.exit(130)

    try:
        _run_pipeline(
            file_paths=[xml_path],
            report=report,
            output=output,
            enrich=enrich,
            deep=deep,
            output_format=output_format,
            show_banner=False,  # already printed above for text mode
        )
    finally:
        # Always clean up the temp XML, even on display/pipeline failure.
        try:
            xml_path.unlink(missing_ok=True)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# update command
# ---------------------------------------------------------------------------

@cli.command("update")
@click.option(
    "--check-only",
    is_flag=True,
    help="Check for a release without changing the current installation.",
)
def update_command(check_only: bool):
    """Check for and install the latest VulnMind GitHub release.

    Pip and pipx installations can be updated directly. Source checkouts and
    system-package installations receive commands appropriate to their install
    method instead of being modified behind the package manager's back.
    """
    from vulnmind.updater import (
        RELEASES_URL,
        check_for_update,
        detect_install_method,
        get_update_plan,
        perform_update,
    )

    with console.status("[bold]Checking GitHub releases...[/bold]"):
        status = check_for_update(force=True)

    if status is None:
        console.print(
            "[yellow]Could not check for updates.[/yellow] "
            f"Visit {RELEASES_URL} to check manually."
        )
        raise click.exceptions.Exit(1)

    latest = status["latest"]
    if not status.get("newer"):
        console.print(
            f"[green]VulnMind {__version__} is up to date.[/green] "
            f"Latest release: {latest}."
        )
        return

    console.print(
        f"[yellow]Update available:[/yellow] {__version__} → [bold]{latest}[/bold]"
    )
    if check_only:
        console.print(RELEASES_URL)
        return

    method = detect_install_method()
    plan = get_update_plan(method, latest_version=latest)
    if not plan.can_auto_update:
        console.print(Panel(
            plan.instructions,
            title=f"Manual update required ({method})",
            border_style="yellow",
        ))
        raise click.exceptions.Exit(1)

    console.print(f"[dim]{plan.instructions}[/dim]")
    with console.status("[bold]Installing update...[/bold]"):
        result = perform_update(method, latest_version=latest)

    if result.success:
        console.print(f"[green]{result.message}[/green]")
        return
    console.print(f"[red]{result.message}[/red]")
    raise click.exceptions.Exit(1)


# ---------------------------------------------------------------------------
# Shared analyze/scan pipeline
# ---------------------------------------------------------------------------

def _run_pipeline(
    file_paths: list[Path],
    report: str | None,
    output: str,
    enrich: bool,
    deep: bool,
    output_format: str,
    show_banner: bool,
) -> None:
    """
    Parse → match → [NVD] → exploit intelligence → [AI] → render.

    Used by both `analyze` (user-supplied files) and `scan` (one temp XML file
    produced by nmap).
    """
    if show_banner and output_format == "text":
        print_banner()

    cfg = Config.load()

    # Text output can check for releases unless the user opts out. Parsing and
    # matching overlap the bounded request; JSON mode never performs this check.
    update_check_started = (
        output_format == "text" and cfg.update_checks_enabled
    )
    if update_check_started:
        from vulnmind.updater import start_check
        start_check()

    # Only check for API key if --enrich was requested
    if enrich and not cfg.groq_api_key:
        if output_format == "json":
            _print_error(
                "No API key configured. Run: vulnmind config set-key <your-key>",
                output_format,
            )
        else:
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
    try:
        # Load the complete set in one call so cross-file IDs share one dedupe
        # set. Calling load_files once per input silently reset deduplication.
        all_findings = load_files(file_paths)
    except Exception as e:
        _print_error(f"Error parsing scanner input: {e}", output_format)
        sys.exit(1)

    if not all_findings:
        if report == "pdf":
            _save_pdf([], output, output_format)
        if output_format == "json":
            import json as _json
            sys.stdout.write(_json.dumps([]) + "\n")
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
            if update_check_started:
                _show_update_notice()
        return

    # --- Knowledge base match (always runs, offline) ---
    findings = match_findings(all_findings)

    # --- NVD live CVE lookup (if --deep) ---
    if deep:
        findings = _nvd_enrich(findings, output_format)

    # --- Exploit intelligence (cached offline; network refresh in --deep) ---
    findings = _exploit_intel_enrich(
        findings,
        output_format=output_format,
        allow_network=deep,
    )

    # --- AI enrich if requested ---
    if enrich:
        from vulnmind.ai import enrich_findings
        findings = enrich_findings(
            findings,
            cfg,
            deep=deep,
            quiet=output_format == "json",
        )

    if report == "pdf":
        _save_pdf(findings, output, output_format)

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

    # --- Update notice (shown last, after everything else) ---
    if update_check_started:
        _show_update_notice()


def _save_pdf(findings, output, output_format):
    """Write a requested report before emitting JSON, with clean error output."""
    from vulnmind.report import generate_pdf
    try:
        generate_pdf(findings, output)
    except Exception as exc:
        _print_error(f"Could not generate PDF report: {exc}", output_format)
        raise click.exceptions.Exit(1) from exc
    if output_format == "text":
        console.print(f"\n[green]Report saved:[/green] {escape(output)}")


def _show_update_notice() -> None:
    """Render a completed release check without affecting structured output."""
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


def _exploit_intel_enrich(
    findings: list,
    *,
    output_format: str,
    allow_network: bool,
) -> list:
    """Apply offline caches and optionally refresh KEV/ExploitDB data."""
    from vulnmind.enrichers import enrich_with_exploit_intelligence

    if output_format == "json" or not allow_network:
        return enrich_with_exploit_intelligence(
            findings,
            allow_network=allow_network,
        )

    with console.status(
        "[bold]Refreshing CISA KEV and ExploitDB intelligence...[/bold]"
    ):
        return enrich_with_exploit_intelligence(findings, allow_network=True)


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


@config.command("set-update-checks")
@click.argument("state", type=click.Choice(["on", "off"]))
def config_set_update_checks(state: str):
    """Enable or disable release checks during normal text-mode runs."""
    cfg = Config.load()
    cfg.set("update_checks", state == "on")
    cfg.save()
    console.print(f"[green]Automatic update checks {state}.[/green]")


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
    priority_badge = f"[{color}]{escape(priority.upper())}[/{color}]"

    lines = []

    service_str = rf"  \[{escape(finding.service)}]" if finding.service else ""
    target = format_target(finding.host, finding.port)
    lines.append(f"[dim]Target:[/dim] [bold]{escape(target)}[/bold]{service_str}")
    confidence = (finding.confidence or "weak").replace("-", " ").title()
    lines.append(f"[dim]Confidence:[/dim] [bold]{escape(confidence)}[/bold]")

    if finding.cve_ids:
        lines.append(f"[dim]CVEs:[/dim]   [cyan]{escape(', '.join(finding.cve_ids))}[/cyan]")

    if finding.cvss_score is not None:
        lines.append(f"[dim]CVSS:[/dim]   [bold]{finding.cvss_score:.1f}[/bold]")

    intel_tags = []
    if finding.actively_exploited:
        intel_tags.append("[bold red]Known Exploited CVE — CISA KEV[/bold red]")
    if finding.exploit_available:
        intel_tags.append("[yellow]Public Exploit Reference[/yellow]")
    if finding.metasploit_available:
        intel_tags.append("[red]Metasploit Module[/red]")
    if intel_tags:
        lines.append(f"[dim]Threat intel:[/dim] {'  ·  '.join(intel_tags)}")

    if finding.priority_reason:
        lines.append(f"[dim]Why {escape(finding.priority or 'this priority')}:[/dim] [dim italic]{escape(finding.priority_reason)}[/dim italic]")

    lines.append("")

    if finding.ai_explanation:
        lines.append(escape(finding.ai_explanation))
    else:
        lines.append(f"[dim]{escape(finding.description)}[/dim]")

    if finding.remediation:
        lines.append("")
        lines.append("[bold]Remediation:[/bold]")
        lines.append(f"  [blue]{escape(finding.remediation)}[/blue]")

    if finding.suggested_commands:
        lines.append("")
        lines.append("[bold]Next steps:[/bold]")
        for cmd in finding.suggested_commands:
            lines.append(f"  [green]$[/green] [white]{escape(cmd)}[/white]")

    if finding.metasploit_modules:
        lines.append("")
        lines.append("[bold]Metasploit:[/bold]")
        for mod in finding.metasploit_modules:
            lines.append(f"  [red]msf[/red] [dim]>[/dim] use {escape(mod)}")

    if finding.false_positive_likelihood in ("medium", "high"):
        lines.append("")
        fp_color = "yellow" if finding.false_positive_likelihood == "medium" else "orange1"
        lines.append(f"[{fp_color}]! False positive likelihood: {finding.false_positive_likelihood}[/{fp_color}]")
        if finding.false_positive_reason:
            lines.append(f"[dim]  {escape(finding.false_positive_reason)}[/dim]")

    console.print(Panel(
        "\n".join(lines),
        title=f"{priority_badge}  [bold]{escape(finding.title)}[/bold]",
        border_style=color,
        padding=(1, 2),
    ))
    console.print()
