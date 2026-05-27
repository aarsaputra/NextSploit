#!/usr/bin/env python3
"""
NextSploit — Next.js Vulnerability Scanner & Exploit Tool
Version 1.0.0

Unified tool combining multiple Next.js CVE scanners:
  - CVE-2025-29927: Middleware Authorization Bypass
  - CVE-2025-57822: Server-Side Request Forgery (SSRF)
  - CVE-2025-55183: Source Code Exposure
  - CVE-2025-55184: Denial of Service (Passive Detection)
  - RSC Protocol & Server Actions Attack

Usage:
  python nextsploit.py -t https://target.com --all
  python nextsploit.py -t https://target.com --cve 29927,57822 -v
  python nextsploit.py -t https://target.com --fingerprint
  python nextsploit.py -t https://target.com --all -o report.json -vv

Author: @lota1337
Original Concept: AnonKryptiQuz
Version: 2.2.0
"""

import sys
import os
import argparse
import importlib
from datetime import datetime

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import ScanConfig, CVE_DATABASE
from core.output import (
    set_verbosity, log_info, log_success,
    log_warning, log_error, log_critical, print_section,
    print_summary_table, console,
)
from core.reporter import ScanReport, ModuleResult
from modules import MODULE_REGISTRY
from modules.fingerprint import fingerprint
from core.version import APP_NAME, APP_VERSION, APP_AUTHOR
from core.banner import get_banner
from core.updater import check_latest_version, run_self_update



def parse_args():
    parser = argparse.ArgumentParser(
        prog="nextsploit",
        description="NextSploit — Next.js Vulnerability Scanner & Exploit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t https://target.com --all                    Full scan
  %(prog)s -t https://target.com --cve 29927              Single CVE scan
  %(prog)s -t https://target.com --cve 29927,57822 -v     Multi CVE, verbose
  %(prog)s -t https://target.com --fingerprint             Version detection only
  %(prog)s -t https://target.com --all -o report.json      Save JSON report
  %(prog)s -t https://target.com --all -o report.html -vv  HTML report, extra verbose
  %(prog)s -t https://target.com --all --proxy http://127.0.0.1:8080

CVE Modules:
  29927   Middleware Auth Bypass (Critical)
  57822   SSRF via Headers (High)
  55183   Source Code Exposure (High)
  55184   DoS Detection — Passive (Medium)
  rsc     RSC Protocol & Server Actions (High)
        """,
    )

    # ─── Target ──────────────────────────────────────────────────────────
    target_group = parser.add_argument_group("Target")
    target_group.add_argument(
        "-t", "--target",
        help="Target URL (e.g., https://target.com)",
    )
    target_group.add_argument(
        "-T", "--target-file",
        help="File containing target URLs (one per line)",
    )

    # ─── Scan Mode ───────────────────────────────────────────────────────
    scan_group = parser.add_argument_group("Scan Mode")
    scan_group.add_argument(
        "--all",
        action="store_true",
        help="Run all scanner modules",
    )
    scan_group.add_argument(
        "--cve",
        help="Comma-separated CVE short IDs to scan (e.g., 29927,57822,rsc)",
    )
    scan_group.add_argument(
        "--fingerprint",
        action="store_true",
        help="Only fingerprint Next.js version (no exploit)",
    )

    # ─── Output ──────────────────────────────────────────────────────────
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-o", "--output",
        help="Save report to file (.json, .html, .txt)",
    )
    output_group.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v verbose, -vv extra verbose)",
    )
    output_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress banner and non-essential output",
    )

    # ─── Connection ──────────────────────────────────────────────────────
    conn_group = parser.add_argument_group("Connection")
    conn_group.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    conn_group.add_argument(
        "--threads",
        type=int,
        default=10,
        help="Max concurrent threads (default: 10)",
    )
    conn_group.add_argument(
        "--proxy",
        help="HTTP/HTTPS proxy (e.g., http://127.0.0.1:8080)",
    )
    conn_group.add_argument(
        "--user-agent",
        dest="user_agent",
        help="Custom User-Agent string",
    )
    conn_group.add_argument(
        "--no-verify",
        action="store_true",
        help="Disable SSL certificate verification",
    )

    # ─── Info ────────────────────────────────────────────────────────────
    info_group = parser.add_argument_group("Info")
    info_group.add_argument(
        "--list-modules",
        action="store_true",
        help="List all available scanner modules",
    )
    info_group.add_argument(
        "--update",
        action="store_true",
        help="Perform self-update via git pull and reinstall requirements",
    )
    info_group.add_argument(
        "--no-update-check",
        dest="no_update_check",
        action="store_true",
        help="Disable automatic update checking on startup",
    )

    # ─── Exploit (AnonKryptiQuz integration) ─────────────────────────────
    exploit_group = parser.add_argument_group("Exploit (AnonKryptiQuz integration)")
    exploit_group.add_argument(
        "--browser",
        action="store_true",
        help=(
            "After CVE-2025-29927 bypass is confirmed (CRITICAL), automatically "
            "open Chrome with the x-middleware-subrequest header pre-set "
            "[requires: selenium + chromedriver]. "
            "Browser exploit engine by AnonKryptiQuz/NextSploit."
        ),
    )

    return parser.parse_args()



def list_modules():
    """Print available modules."""
    from rich.table import Table
    from rich import box

    table = Table(
        title="[bold]Available Scanner Modules[/bold]",
        box=box.ROUNDED,
        border_style="cyan",
    )
    table.add_column("ID", style="bold cyan", min_width=8)
    table.add_column("CVE / Name", style="bold white", min_width=18)
    table.add_column("Title", style="white", min_width=30)

    for mod_id, mod_info in MODULE_REGISTRY.items():
        table.add_row(mod_id, mod_info["name"], mod_info["title"])

    console.print()
    console.print(table)
    console.print()


def validate_target(url: str) -> str:
    """Validate and normalize target URL."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")


def run_module(mod_id: str, config: ScanConfig) -> ModuleResult:
    """Dynamically import and run a scanner module."""
    mod_info = MODULE_REGISTRY.get(mod_id)
    if not mod_info:
        log_error(f"Unknown module: {mod_id}")
        return ModuleResult(
            cve=mod_id, title="Unknown", severity="UNKNOWN",
            status="ERROR", error=f"Module '{mod_id}' not found",
        )

    try:
        module = importlib.import_module(mod_info["module"])
        scan_func = getattr(module, mod_info["function"])
        return scan_func(config)
    except Exception as e:
        log_error(f"Module {mod_id} failed: {e}")
        import traceback
        if config.verbosity >= 1:
            traceback.print_exc()
        return ModuleResult(
            cve=mod_info["name"], title=mod_info["title"],
            severity="UNKNOWN", status="ERROR", error=str(e),
        )


def scan_target(target: str, args) -> ScanReport:
    """Run full scan pipeline on a single target."""
    target = validate_target(target)

    # Build config
    config = ScanConfig(
        target=target,
        timeout=args.timeout,
        threads=args.threads,
        verbosity=args.verbose,
        proxy=args.proxy,
        verify_ssl=not args.no_verify,
        output_file=args.output,
        browser_exploit=getattr(args, "browser", False),
    )
    if args.user_agent:
        config.user_agent = args.user_agent

    report = ScanReport(target)

    # ─── Fingerprint ─────────────────────────────────────────────────────
    fp_result = fingerprint(config)
    report.nextjs_version = fp_result["version"]
    report.build_id = fp_result["build_id"]
    report.vuln_matrix = fp_result["vuln_matrix"]

    if args.fingerprint:
        # Fingerprint only mode — stop here
        return report

    # ─── Determine modules to run ────────────────────────────────────────
    if args.all:
        modules_to_run = list(MODULE_REGISTRY.keys())
    elif args.cve:
        modules_to_run = [c.strip() for c in args.cve.split(",")]
        # Validate
        invalid = [m for m in modules_to_run if m not in MODULE_REGISTRY]
        if invalid:
            log_error(f"Unknown module(s): {', '.join(invalid)}")
            log_info(f"Available: {', '.join(MODULE_REGISTRY.keys())}")
            modules_to_run = [m for m in modules_to_run if m in MODULE_REGISTRY]
    else:
        log_warning("No scan mode specified. Use --all or --cve <id>")
        log_info("Use --list-modules to see available modules")
        return report

    # ─── Run modules ─────────────────────────────────────────────────────
    print_section(
        "Running Scanner Modules",
        f"Modules: {', '.join(modules_to_run)} | Target: {target}"
    )

    for mod_id in modules_to_run:
        mod_result = run_module(mod_id, config)
        report.add_result(mod_result)

    # ─── Summary ─────────────────────────────────────────────────────────
    print_summary_table(report.get_summary_rows())

    total_findings = sum(r.finding_count for r in report.module_results)
    vuln_modules = sum(1 for r in report.module_results if r.status == "VULNERABLE")

    if vuln_modules > 0:
        log_critical(
            f"Scan complete: [bold]{vuln_modules}[/bold] vulnerable modules, "
            f"[bold]{total_findings}[/bold] total findings"
        )
    else:
        log_success("Scan complete: No vulnerabilities detected")

    return report


def main():
    args = parse_args()

    # Set verbosity globally
    set_verbosity(args.verbose)

    # Self-update mode
    if args.update:
        run_self_update()
        return

    # Banner
    if not args.quiet:
        console.print(get_banner())

    # Update check
    if not args.no_update_check and not args.quiet:
        check_latest_version()

    # List modules mode
    if args.list_modules:
        list_modules()
        return

    # Validate target
    if not args.target and not args.target_file:
        log_error("No target specified. Use -t <url> or -T <file>")
        sys.exit(1)

    # Create reports directory
    os.makedirs("reports", exist_ok=True)

    # ─── Single target mode ──────────────────────────────────────────────
    if args.target:
        log_info(f"Target: [bold]{args.target}[/bold]")
        log_info(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        report = scan_target(args.target, args)

        if args.output:
            report.save(args.output)

        log_info(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # ─── Multi-target mode ───────────────────────────────────────────────
    elif args.target_file:
        if not os.path.isfile(args.target_file):
            log_error(f"Target file not found: {args.target_file}")
            sys.exit(1)

        with open(args.target_file) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        log_info(f"Loaded [bold]{len(targets)}[/bold] targets from {args.target_file}")

        for i, target_url in enumerate(targets, 1):
            log_info(f"\n{'='*60}")
            log_info(f"Target [{i}/{len(targets)}]: [bold]{target_url}[/bold]")
            log_info(f"{'='*60}")

            report = scan_target(target_url, args)

            # Auto-save per target
            if args.output:
                ext = os.path.splitext(args.output)[1] or ".json"
                base = os.path.splitext(args.output)[0]
                safe_target = target_url.replace("https://", "").replace("http://", "").replace("/", "_")
                per_target_file = f"{base}_{safe_target}{ext}"
                report.save(per_target_file)

    console.print(f"\n[dim]─── {APP_NAME} v{APP_VERSION} | @{APP_AUTHOR} | Based on work by @AnonKryptiQuz ───[/dim]\n")


if __name__ == "__main__":
    main()

