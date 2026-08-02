"""
nextsploit/phases/validation.py — Phase 0: Target Validation.
"""

import socket
from urllib.parse import urlparse
from nextsploit.core.context import ScanContext
from nextsploit.core.exceptions import PipelineException
from nextsploit.core.logger import log_success, log_info


class TargetValidationPhase:
    """
    Phase 0: Target Validation.
    Checks URL structure, resolves DNS, and validates target availability.
    """
    name = "Target Validation"

    def run(self, context: ScanContext) -> None:
        url = context.target
        if not url:
            raise PipelineException("Target URL cannot be empty.")

        # Parse URL
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            raise PipelineException(f"Invalid URL structure: {url}")

        hostname = parsed.netloc.split(":")[0]
        log_info(f"Resolving DNS for host: [bold]{hostname}[/bold]...")

        try:
            ip = socket.gethostbyname(hostname)
            context.profile.hostname = hostname
            context.profile.ip = ip
            log_success(f"DNS resolved successfully. IP Address: [bold green]{ip}[/bold green]")
        except socket.gaierror as e:
            raise PipelineException(f"Failed to resolve DNS for hostname '{hostname}': {e}")

        # Send test request to verify connectivity
        log_info("Testing HTTP connectivity...")
        try:
            resp = context.session.get(url, timeout=context.config.timeout, verify=context.config.verify_ssl)
            log_success(f"HTTP connectivity verified. Status Code: [bold green]{resp.status_code}[/bold green]")
            context.profile.evidence["initial_response_code"] = resp.status_code
        except Exception as e:
            raise PipelineException(f"HTTP connection test failed: {e}")
