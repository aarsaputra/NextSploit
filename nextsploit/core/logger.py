"""
nextsploit/core/logger.py — Centralized Console Logging for NextSploit.
"""

from rich.console import Console

console = Console()
_verbosity = 0


def set_verbosity(level: int):
    """Set global verbosity level."""
    global _verbosity
    _verbosity = level


def get_verbosity() -> int:
    """Get current verbosity level."""
    return _verbosity


def log_info(msg: str):
    """Log informational message."""
    console.print(f"[bold cyan][*][/bold cyan] {msg}")


def log_success(msg: str):
    """Log success message."""
    console.print(f"[bold green][+][/bold green] {msg}")


def log_warning(msg: str):
    """Log warning message."""
    console.print(f"[bold yellow][!][/bold yellow] {msg}")


def log_error(msg: str):
    """Log error message."""
    console.print(f"[bold red][ERR][/bold red] {msg}")


def log_critical(msg: str):
    """Log critical failure message."""
    console.print(f"[bold red][!!][/bold red] [bold red]{msg}[/bold red]")


def log_debug(msg: str):
    """Log debug message (visible at verbosity >= 1)."""
    if _verbosity >= 1:
        console.print(f"[dim cyan][DBG][/dim cyan] [dim]{msg}[/dim]")


def log_trace(msg: str):
    """Log trace message (visible at verbosity >= 2)."""
    if _verbosity >= 2:
        console.print(f"[dim magenta][TRC][/dim magenta] [dim]{msg}[/dim]")


def log_status(code: int, path: str, extra: str = ""):
    """Print HTTP response status with color coding."""
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
        line += f" ({extra})"
    console.print(line)
