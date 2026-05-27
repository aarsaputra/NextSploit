# core/banner.py
from core.version import APP_VERSION, APP_AUTHOR

BANNER = f"""
[bold red]╔══════════════════════════════════════════════════════════════╗[/bold red]
[bold red]║                                                              ║[/bold red]
[bold red]║     ███╗   ██╗███████╗██╗  ██╗████████╗███████╗██████╗       ║[/bold red]
[bold red]║     ████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝██╔══██╗      ║[/bold red]
[bold red]║     ██╔██╗ ██║█████╗   ╚███╔╝    ██║   ███████╗██████╔╝      ║[/bold red]
[bold red]║     ██║╚██╗██║██╔══╝   ██╔██╗    ██║   ╚════██║██╔═══╝       ║[/bold red]
[bold red]║     ██║ ╚████║███████╗██╔╝ ██╗   ██║   ███████║██║           ║[/bold red]
[bold red]║     ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝           ║[/bold red]
[bold red]║                                                              ║[/bold red]
[bold red]║     [bold white]╔═══════════════════════════════════════════════════╗[/bold white]     ║[/bold red]
[bold red]║     [bold white]║  Next.js Multi-CVE Security Auditing Framework    ║[/bold white]     ║[/bold red]
[bold red]║     [bold white]║  Version {APP_VERSION:<8} by {APP_AUTHOR:<23}     ║[/bold white]     ║[/bold red]
[bold red]║     [bold white]╚═══════════════════════════════════════════════════╝[/bold white]     ║[/bold red]
[bold red]╚══════════════════════════════════════════════════════════════╝[/bold red]
"""

def get_banner() -> str:
    return BANNER
