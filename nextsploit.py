#!/usr/bin/env python3
"""
NextSploit — Next.js Vulnerability Scanner & Exploit Tool
Version 2.2.0

Unified tool combining multiple Next.js CVE scanners:
  - CVE-2025-29927: Middleware Authorization Bypass
  - CVE-2025-57822: Server-Side Request Forgery (SSRF)
  - CVE-2025-55183: Source Code Exposure
  - CVE-2025-55184: Denial of Service (Passive Detection)
  - RSC Protocol & Server Actions Attack

Usage:
  python nextsploit.py -t https://target.com --all
  python nextsploit.py -t https://target.com --cve 29927,57822 -v
  python nextsploit.py -c config.json
  python nextsploit.py -t https://target.com --all -o report.json -vv

Author: @lota1337
Original Concept: AnonKryptiQuz
"""

import sys
import os
import json
import argparse
import importlib
from datetime import datetime
from typing import Dict, Any

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


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="nextsploit",
        description="NextSploit — Next.js Vulnerability Scanner & Exploit Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t https://target.com --all                    Full scan
  %(prog)s -c config.json                                 Scan using config file
  %(prog)s -t https://target.com --cve 29927,57822 -v     Multi CVE, verbose
  %(prog)s -t https://target.com --fingerprint            Version detection only
        """,
    )

    # ─── Core Options ────────────────────────────────────────────────────────
    core_group = parser.add_argument_group("Core")
    core_group.add_argument(
        "-t", "--target",
        help="Target URL (e.g., https://target.com)",
    )
    core_group.add_argument(
        "-T", "--target-file",
        help="File containing target URLs (one per line)",
    )
    core_group.add_argument(
        "-c", "--config",
        help="Path to JSON configuration file for automation",
    )
    core_group.add_argument(
        "-V", "--version",
        action="version",
        version=f"{APP_NAME} v{APP_VERSION} by @{APP_AUTHOR}",
        help="Show program's version number and exit",
    )

    # ─── Scan Mode ───────────────────────────────────────────────────────────
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

    # ─── Output ──────────────────────────────────────────────────────────────
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

    # ─── Connection ──────────────────────────────────────────────────────────
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

    # ─── Info & Automation ───────────────────────────────────────────────────
    info_group = parser.add_argument_group("Info & Automation")
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

    # ─── Exploit (AnonKryptiQuz integration) ─────────────────────────────────
    exploit_group = parser.add_argument_group("Exploit Engine")
    exploit_group.add_argument(
        "--browser",
        action="store_true",
        help="Trigger Selenium browser exploit on critical bypass detection",
    )

    return parser.parse_args()


def load_config_file(filepath: str) -> Dict[str, Any]:
    """Parse JSON configuration for CI/CD automation and overriding defaults."""
    if not os.path.isfile(filepath):
        log_error(f"Configuration file not found: {filepath}")
        sys.exit(1)
        
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        log_error(f"Syntax error in JSON config '{filepath}': {e}")
        sys.exit(1)
    except Exception as e:
        log_error(f"Failed to read config file '{filepath}': {e}")
        sys.exit(1)


def build_scan_config(target: str, args: argparse.Namespace, file_cfg: Dict[str, Any]) -> ScanConfig:
    """Factory function to build ScanConfig by merging CLI args and JSON file config."""
    # Priority: CLI arguments (if explicitly set) > File Config > Defaults
    
    timeout = file_cfg.get("timeout", args.timeout) if args.timeout == 10 else args.timeout
    threads = file_cfg.get("threads", args.threads) if args.threads == 10 else args.threads
    proxy = args.proxy or file_cfg.get("proxy")
    output = args.output or file_cfg.get("output")
    user_agent = args.user_agent or file_cfg.get("user_agent")
    
    # Booleans
    verify_ssl = file_cfg.get("verify_ssl", not args.no_verify) if not args.no_verify else False
    browser_exploit = getattr(args, "browser", False) or file_cfg.get("browser", False)
    
    config = ScanConfig(
        target=target,
        timeout=timeout,
        threads=threads,
        verbosity=args.verbose or file_cfg.get("verbose", 0),
        proxy=proxy,
        verify_ssl=verify_ssl,
        output_file=output,
        browser_exploit=browser_exploit,
    )
    if user_agent:
        config.user_agent = user_agent
        
    return config


def list_modules() -> None:
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
    """Dynamically import and execute a scanner module."""
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


def scan_target(target: str, config: ScanConfig, run_all: bool, cve_args: str, run_fingerprint: bool) -> ScanReport:
    """Execute the core scanning workflow for a specific target."""
    target = validate_target(target)
    config.target = target
    report = ScanReport(target)

    # ─── Fingerprint Phase ───────────────────────────────────────────────────
    fp_result = fingerprint(config)
    report.nextjs_version = fp_result["version"]
    report.build_id = fp_result["build_id"]
    report.vuln_matrix = fp_result["vuln_matrix"]

    if run_fingerprint:
        return report

    # ─── Module Selection Phase ──────────────────────────────────────────────
    if run_all:
        modules_to_run = list(MODULE_REGISTRY.keys())
    elif cve_args:
        modules_to_run = [c.strip() for c in cve_args.split(",")]
        # Validate existence
        invalid = [m for m in modules_to_run if m not in MODULE_REGISTRY]
        if invalid:
            log_error(f"Unknown module(s): {', '.join(invalid)}")
            log_info(f"Available: {', '.join(MODULE_REGISTRY.keys())}")
            modules_to_run = [m for m in modules_to_run if m in MODULE_REGISTRY]
    else:
        log_warning("No scan mode specified. Use --all, --cve <id>, or configure via JSON.")
        return report

    # ─── Execution Phase ─────────────────────────────────────────────────────
    print_section(
        "Running Scanner Modules",
        f"Modules: {', '.join(modules_to_run)} | Target: {target}"
    )

    for mod_id in modules_to_run:
        mod_result = run_module(mod_id, config)
        report.add_result(mod_result)

    # ─── Reporting Phase ─────────────────────────────────────────────────────
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


def main() -> None:
    args = parse_args()

    # Base configuration from file (if provided)
    file_cfg = {}
    if args.config:
        file_cfg = load_config_file(args.config)

    # Set verbosity globally
    merged_verbosity = args.verbose or file_cfg.get("verbose", 0)
    set_verbosity(merged_verbosity)

    # Interactive Flags
    if args.update:
        run_self_update()
        return

    if not args.quiet:
        console.print(get_banner())

    if not args.no_update_check and not args.quiet:
        check_latest_version()

    if args.list_modules:
        list_modules()
        return

    # Determine targets
    targets = []
    if args.target:
        targets.append(args.target)
    elif args.target_file:
        if not os.path.isfile(args.target_file):
            log_error(f"Target file not found: {args.target_file}")
            sys.exit(1)
        with open(args.target_file) as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    elif "targets" in file_cfg:
        targets = file_cfg["targets"]

    if not targets:
        log_error("No target specified. Use -t <url>, -T <file>, or specify 'targets' in --config")
        sys.exit(1)

    # Merge scan logic parameters
    run_all = args.all or file_cfg.get("all", False)
    cve_args = args.cve or file_cfg.get("cve", "")
    run_fingerprint = args.fingerprint or file_cfg.get("fingerprint", False)

    # Create reports directory
    os.makedirs("reports", exist_ok=True)

    # Execute Scan
    log_info(f"Loaded [bold]{len(targets)}[/bold] target(s). Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    for i, target_url in enumerate(targets, 1):
        if len(targets) > 1:
            log_info(f"\n{'='*60}")
            log_info(f"Target [{i}/{len(targets)}]: [bold]{target_url}[/bold]")
            log_info(f"{'='*60}")

        # Build clean config specifically for this target
        config = build_scan_config(target_url, args, file_cfg)
        
        # Run execution pipeline
        report = scan_target(target_url, config, run_all, cve_args, run_fingerprint)

        # Output handling
        output_path = config.output_file
        if output_path:
            if len(targets) > 1:
                # Auto-append target name to prevent overwriting in multi-target scans
                ext = os.path.splitext(output_path)[1] or ".json"
                base = os.path.splitext(output_path)[0]
                safe_target = target_url.replace("https://", "").replace("http://", "").replace("/", "_")
                output_path = f"{base}_{safe_target}{ext}"
                
            report.save(output_path)

    log_info(f"Finished all scans at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print(f"\n[dim]─── {APP_NAME} v{APP_VERSION} | @{APP_AUTHOR} | Based on work by @AnonKryptiQuz ───[/dim]\n")


if __name__ == "__main__":
    main()
