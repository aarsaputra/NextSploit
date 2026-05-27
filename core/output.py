#!/usr/bin/env python3
"""
NextSploit — Rich Console Output & Logging
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box

console = Console()

# Verbosity level (set by CLI)
_verbosity = 0


def set_verbosity(level: int):
    global _verbosity
    _verbosity = level


def get_verbosity() -> int:
    return _verbosity


# ─── Banner ──────────────────────────────────────────────────────────────────

BANNER = r"""
[bold red]
    _   __          __  _____       __      _ __ 
   / | / /__  _  __/ /_/ ___/____  / /___  (_) /_
  /  |/ / _ \| |/_/ __/\__ \/ __ \/ / __ \/ / __/
 / /|  /  __/>  </ /_ ___/ / /_/ / / /_/ / / /_  
/_/ |_/\___/_/|_|\__//____/ .___/_/\____/_/\__/  
                         /_/                      
[/bold red]
[dim white]  ╔══════════════════════════════════════════════════╗
             ║  Next.js Vulnerability Scanner & Exploit Tool    ║
             ║  Version 1.0.0 | by @lota1337                    ║
             ╚══════════════════════════════════════════════════╝[/dim white]
"""


def print_banner():
    console.print(BANNER)


# ─── Logging Functions ───────────────────────────────────────────────────────

def log_info(msg: str):
    console.print(f"[bold cyan][*][/bold cyan] {msg}")


def log_success(msg: str):
    console.print(f"[bold green][+][/bold green] {msg}")


def log_warning(msg: str):
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def log_critical(msg: str):
    console.print(f"[bold red][!!][/bold red] [bold red]{msg}[/bold red]")


def log_error(msg: str):
    console.print(f"[bold red][ERR][/bold red] {msg}")


def log_debug(msg: str):
    """Only prints when verbosity >= 1"""
    if _verbosity >= 1:
        console.print(f"[dim cyan][DBG][/dim cyan] [dim]{msg}[/dim]")


def log_trace(msg: str):
    """Only prints when verbosity >= 2"""
    if _verbosity >= 2:
        console.print(f"[dim magenta][TRC][/dim magenta] [dim]{msg}[/dim]")


def log_status(code: int, path: str, extra: str = ""):
    """Print HTTP status with color coding."""
    if code == 200:
        color = "green"
    elif code in (301, 302, 307, 308):
        color = "yellow"
    elif code in (401, 403):
        color = "red"
    elif code == 404:
        color = "dim"
    elif code >= 500:
        color = "bold red"
    else:
        color = "white"

    line = f"[{color}][{code}][/{color}] {path}"
    if extra:
        line += f" [dim]({extra})[/dim]"
    console.print(f"  {line}")


# ─── Section Headers ────────────────────────────────────────────────────────

def print_section(title: str, subtitle: str = ""):
    console.print()
    panel_text = f"[bold white]{title}[/bold white]"
    if subtitle:
        panel_text += f"\n[dim]{subtitle}[/dim]"
    console.print(Panel(panel_text, border_style="cyan", box=box.DOUBLE_EDGE))


def print_module_header(cve_id: str, title: str, severity: str):
    sev_colors = {
        "CRITICAL": "bold red",
        "HIGH": "bold yellow",
        "MEDIUM": "yellow",
        "LOW": "green",
    }
    color = sev_colors.get(severity, "white")

    console.print()
    console.print(
        Panel(
            f"[bold white]{cve_id}[/bold white] — {title}\n"
            f"Severity: [{color}]{severity}[/{color}]",
            border_style=color.replace("bold ", ""),
            box=box.HEAVY,
            title="[bold]Scanner Module[/bold]",
            title_align="left",
        )
    )


# ─── Summary Table ──────────────────────────────────────────────────────────

def print_summary_table(findings: list):
    """Print a summary table of all findings."""
    table = Table(
        title="[bold]Scan Results Summary[/bold]",
        box=box.DOUBLE_EDGE,
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("CVE / Module", style="bold white", min_width=18)
    table.add_column("Title", style="white", min_width=25)
    table.add_column("Severity", justify="center", min_width=10)
    table.add_column("Status", justify="center", min_width=14)
    table.add_column("Findings", justify="center", min_width=8)

    sev_colors = {
        "CRITICAL": "bold red",
        "HIGH": "bold yellow",
        "MEDIUM": "yellow",
        "LOW": "green",
    }

    for f in findings:
        sev = f.get("severity", "UNKNOWN")
        color = sev_colors.get(sev, "white")
        status = f.get("status", "UNKNOWN")

        if status == "VULNERABLE":
            status_style = "[bold red]⚠ VULNERABLE[/bold red]"
        elif status == "NOT VULNERABLE":
            status_style = "[bold green]✓ SAFE[/bold green]"
        elif status == "ERROR":
            status_style = "[dim red]✗ ERROR[/dim red]"
        else:
            status_style = f"[dim]{status}[/dim]"

        count = f.get("finding_count", 0)
        count_style = f"[bold red]{count}[/bold red]" if count > 0 else f"[dim]{count}[/dim]"

        table.add_row(
            f.get("cve", "N/A"),
            f.get("title", "N/A"),
            f"[{color}]{sev}[/{color}]",
            status_style,
            count_style,
        )

    console.print()
    console.print(table)
    console.print()


# ─── Progress Bar ────────────────────────────────────────────────────────────

def create_progress() -> Progress:
    return Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30, style="cyan", complete_style="bold green"),
        TextColumn("[bold]{task.completed}/{task.total}[/bold]"),
        TimeElapsedColumn(),
        console=console,
    )


# ─── Finding Display ────────────────────────────────────────────────────────

def print_finding(cve: str, detail: str, evidence: dict = None):
    """Print a single finding with evidence."""
    console.print(f"\n  [bold red]▸ FINDING:[/bold red] [bold]{cve}[/bold]")
    console.print(f"    {detail}")

    if evidence and _verbosity >= 1:
        for k, v in evidence.items():
            console.print(f"    [dim cyan]{k}:[/dim cyan] {v}")


def print_vuln_matrix(matrix: list):
    """Print vulnerability matrix table."""
    table = Table(
        title="[bold]Vulnerability Matrix[/bold]",
        box=box.ROUNDED,
        border_style="yellow",
        show_lines=True,
    )
    table.add_column("CVE", style="bold white", min_width=18)
    table.add_column("Type", style="white", min_width=15)
    table.add_column("Fix Version", justify="center", min_width=10)
    table.add_column("Status", justify="center", min_width=16)

    for entry in matrix:
        status = entry.get("status", "UNKNOWN")
        if "VULNERABLE" in status:
            status_style = f"[bold red]{status}[/bold red]"
        elif "PATCHED" in status:
            status_style = f"[bold green]{status}[/bold green]"
        else:
            status_style = f"[dim]{status}[/dim]"

        table.add_row(
            entry["cve"],
            entry["type"],
            entry["fix_version"],
            status_style,
        )

    console.print()
    console.print(table)
