# core/banner.py
from core.version import APP_VERSION, APP_AUTHOR, APP_ORIGINAL_AUTHOR
from rich.panel import Panel
from rich.align import Align
from rich.text import Text

ASCII_ART = """
███╗   ██╗███████╗██╗  ██╗████████╗███████╗██████╗ 
████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝██╔══██╗
██╔██╗ ██║█████╗   ╚███╔╝    ██║   ███████╗██████╔╝
██║╚██╗██║██╔══╝   ██╔██╗    ██║   ╚════██║██╔═══╝ 
██║ ╚████║███████╗██╔╝ ██╗   ██║   ███████║██║     
╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝     
"""

def get_banner() -> Panel:
    text = Text()
    text.append(ASCII_ART, style="bold red")
    text.append("\nNext.js Multi-CVE Security Auditing Framework\n", style="bold white")
    text.append(f"Version {APP_VERSION} by {APP_AUTHOR}\n", style="white")
    text.append(f"Original Concept by {APP_ORIGINAL_AUTHOR}", style="dim white")
    
    panel = Panel(
        Align.center(text),
        border_style="red",
        padding=(1, 2),
        width=70
    )
    return panel
