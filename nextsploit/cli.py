"""
nextsploit/cli.py — CLI entry point, argument parsing, and command routing for NextSploit v4.
"""

import sys
import os
import json
import argparse
import requests
import time
from typing import Dict, Any

from nextsploit.core.version import APP_NAME, APP_VERSION, APP_AUTHOR, APP_DESCRIPTION
from nextsploit.core.config import ScanConfig
from nextsploit.core.context import ScanContext
from nextsploit.core.logger import set_verbosity, log_info, log_error, log_success, console
from nextsploit.pipeline.pipeline import ScanPipeline
from nextsploit.phases.validation import TargetValidationPhase
from nextsploit.phases.recon import ReconPhase
from nextsploit.phases.fingerprint import FingerprintPhase
from nextsploit.phases.active import PluginExecutionPhase
from nextsploit.phases.rule_execution import RuleExecutionPhase


def parse_args() -> argparse.Namespace:
    """Parse CLI arguments with full subcommand routing support."""
    parser = argparse.ArgumentParser(
        prog="nextsploit",
        description=f"{APP_NAME} v{APP_VERSION} — {APP_DESCRIPTION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    # Backwards compatibility: add direct top-level arguments
    parser.add_argument("-t", "--target", help="Target URL (e.g., https://target.com)")
    parser.add_argument("-T", "--target-file", help="File containing target URLs")
    parser.add_argument("-o", "--output", help="Save report to file")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress non-essential output")
    parser.add_argument("--policy", default="safe", choices=["safe", "bugbounty", "pentest", "ci"])
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--threads", type=int, default=10)
    parser.add_argument("--proxy", help="HTTP/HTTPS proxy URL")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--no-verify", action="store_true", help="Disable SSL verification")

    subparsers = parser.add_subparsers(dest="command", help="NextSploit Subcommands")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Run standard target vulnerability scan")
    scan_parser.add_argument("-t", "--target", help="Target URL")
    scan_parser.add_argument("-T", "--target-file", help="File containing target URLs")
    scan_parser.add_argument("-o", "--output", help="Save report to file")
    scan_parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")
    scan_parser.add_argument("-q", "--quiet", action="store_true")
    scan_parser.add_argument("--policy", default="safe", choices=["safe", "bugbounty", "pentest", "ci"])
    scan_parser.add_argument("--timeout", type=int, default=10)
    scan_parser.add_argument("--threads", type=int, default=10)
    scan_parser.add_argument("--proxy", help="HTTP/HTTPS proxy URL")
    scan_parser.add_argument("--user-agent", help="Custom User-Agent")
    scan_parser.add_argument("--no-verify", action="store_true")

    # Command: replay
    replay_parser = subparsers.add_parser("replay", help="Replay findings from a scan report")
    replay_parser.add_argument("report_file", help="Path to JSON scan report manifest")
    replay_parser.add_argument("--only", choices=["critical", "high", "medium", "low"], help="Filter by severity")
    replay_parser.add_argument("--module", help="Filter by specific module ID")
    replay_parser.add_argument("--mode", default="SMART", choices=["STRICT", "SMART", "DIFF"], help="Replay analysis mode")

    # Command: plugin
    plugin_parser = subparsers.add_parser("plugin", help="Manage scanning plugins")
    plugin_sub = plugin_parser.add_subparsers(dest="plugin_cmd", help="Plugin actions")
    
    plugin_sub.add_parser("list", help="List installed plugins")
    
    info_p = plugin_sub.add_parser("info", help="Show plugin details")
    info_p.add_argument("plugin_id", help="Plugin identifier")
    
    verify_p = plugin_sub.add_parser("verify", help="Verify plugin manifest.json")
    verify_p.add_argument("dir", help="Plugin directory")

    doctor_p = plugin_sub.add_parser("doctor", help="Run thorough diagnostics on a plugin sandbox")
    doctor_p.add_argument("dir", help="Plugin directory")

    enable_p = plugin_sub.add_parser("enable", help="Enable a plugin")
    enable_p.add_argument("plugin_id", help="Plugin identifier")

    disable_p = plugin_sub.add_parser("disable", help="Disable a plugin")
    disable_p.add_argument("plugin_id", help="Plugin identifier")

    return parser.parse_args()


def build_config(args: argparse.Namespace) -> ScanConfig:
    """Build ScanConfig dataclass from CLI arguments."""
    config = ScanConfig(
        target=args.target or "",
        target_file=args.target_file,
        policy_name=args.policy,
        timeout=args.timeout,
        threads=args.threads,
        verbosity=args.verbose,
        proxy=args.proxy,
        verify_ssl=not args.no_verify,
        output_file=args.output,
    )
    if args.user_agent:
        config.user_agent = args.user_agent
    return config


def handle_scan(args: argparse.Namespace) -> None:
    """Orchestrates standard scanning sequence."""
    config = build_config(args)
    if not config.target and not config.target_file:
        log_error("Target URL (-t/--target) or target file (-T/--target-file) required for scan.")
        sys.exit(1)

    set_verbosity(config.verbosity)
    log_info(f"{APP_NAME} v{APP_VERSION} - Next.js Security Auditing & Vulnerability Discovery Framework")
    log_info(f"Target selected: {config.target}")

    # Load active Policy
    from nextsploit.services.policy import PolicyEngine
    policy_engine = PolicyEngine()
    policy = policy_engine.load_policy(config.policy_name)

    # Initialize Event Bus & Metrics
    from nextsploit.services.event_bus import EventBus
    from nextsploit.services.metrics import MetricsService
    from nextsploit.core.container import container

    event_bus = EventBus()
    metrics = MetricsService()
    metrics.attach_to_event_bus(event_bus)

    container.register_instance("event_bus", event_bus)
    container.register_instance("metrics", metrics)

    # Initialize Risk Engine
    from nextsploit.services.risk import RiskEngine
    risk_engine = RiskEngine()
    container.register_instance("risk_engine", risk_engine)

    # Create ResourceManager Session
    from nextsploit.services.resource import ResourceManagerSession
    session = ResourceManagerSession(
        event_bus=event_bus,
        rate_limit=policy.get_rate_limit(),
        max_retries=3,
        backoff_factor=1.0,
        cb_threshold=5,
        cb_recovery_time=10.0
    )
    session.headers.update({"User-Agent": config.user_agent or f"NextSploit/{APP_VERSION}"})
    if config.proxy:
        session.proxies.update({"http": config.proxy, "https": config.proxy})

    # Context and Pipeline
    context = ScanContext(config.target, config, session)
    pipeline = ScanPipeline()

    # Load Knowledge Base
    from nextsploit.core.kb import KnowledgeBase
    kb = KnowledgeBase()
    kb.load_all()
    log_info(f"Knowledge Base loaded: {len(kb.fingerprints)} fingerprints, {len(kb.vulnerabilities)} vulnerabilities, {len(kb.heuristics)} heuristics.")

    # Reporter registration
    from nextsploit.services.reporter import ScanReporter, JSONFormatter, MarkdownFormatter, HTMLFormatter, SARIFFormatter, FileExporter
    reporter = ScanReporter()
    container.register_instance("reporter", reporter)

    # Register all Phases
    pipeline.registry.register(TargetValidationPhase())
    pipeline.registry.register(ReconPhase())
    pipeline.registry.register(FingerprintPhase())
    pipeline.registry.register(PluginExecutionPhase())
    pipeline.registry.register(RuleExecutionPhase())

    # Execute
    start_time = time.monotonic()
    try:
        pipeline.run(context)
        log_success("Scan pipeline executed successfully.")
        
        # Display Metrics stats
        stats = metrics.get_stats()
        log_info(f"Scan Telemetry Metrics: Requests={stats['total_requests']}, Responses={stats['responses_received']}, Failures={stats['failed_requests']}, WAF Blocks={stats['waf_blocks']}, Avg Latency={stats['average_latency_ms']}ms, Success Rate={stats['success_rate_percent']}%")
    except Exception as e:
        log_error(f"Scan pipeline execution failed: {e}")
        sys.exit(1)

    duration = time.monotonic() - start_time

    # Export report if requested
    if config.output_file:
        dest = config.output_file
        metadata = {
            "target": config.target,
            "policy": config.policy_name,
            "version": APP_VERSION,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time)),
            "duration": duration,
            "statistics": metrics.get_stats(),
            "profile": {
                "hostname": context.profile.hostname,
                "ip": context.profile.ip,
                "framework_version": context.profile.framework_version,
                "router": context.profile.router,
                "hosting": context.profile.hosting,
                "cdn": context.profile.cdn,
                "waf": context.profile.waf,
                "build_id": context.profile.build_id,
                "server_actions": context.profile.server_actions,
                "rsc": context.profile.rsc,
                "turbopack": context.profile.turbopack,
            }
        }
        
        if dest.endswith(".json"):
            formatter = JSONFormatter()
        elif dest.endswith(".html"):
            formatter = HTMLFormatter()
        elif dest.endswith(".sarif"):
            formatter = SARIFFormatter()
        else:
            formatter = MarkdownFormatter()
            
        content = formatter.format(reporter.get_findings(), metadata)
        try:
            exporter = FileExporter()
            exporter.export(content, dest)
            log_success(f"Report exported successfully to [bold green]{dest}[/bold green]")
        except Exception as e:
            log_error(f"Failed to export report to {dest}: {e}")


def handle_replay(args: argparse.Namespace) -> None:
    """Executes Replay verification of findings from a report manifest file."""
    if not os.path.exists(args.report_file):
        log_error(f"Scan report file not found: {args.report_file}")
        sys.exit(1)

    try:
        with open(args.report_file, "r") as f:
            report = json.load(f)
    except Exception as e:
        log_error(f"Failed to parse JSON report: {e}")
        sys.exit(1)

    findings = report.get("findings", [])
    if not findings:
        log_info("No findings present inside the scan report to replay.")
        return

    from nextsploit.services.replay import ReplayEngine
    replay_engine = ReplayEngine()

    log_info(f"Replaying findings using mode: [bold cyan]{args.mode}[/bold cyan]...")

    updated_count = 0
    for finding in findings:
        fid = finding.get("id", "")
        uuid_str = finding.get("metadata", {}).get("uuid", "")
        sev = finding.get("severity", "").lower()
        module = finding.get("metadata", {}).get("module", "")

        # Apply filters
        if args.only and sev != args.only.lower():
            continue
        if args.module and module != args.module:
            continue

        log_info(f"Executing replay for {fid} ({uuid_str})...")
        replay_res = replay_engine.replay_finding(finding, mode=args.mode)
        
        # Update report findings fields
        finding["replay"] = replay_res
        
        # Update timeline in report finding
        timestamp = time.strftime("%H:%M:%S", time.gmtime())
        finding.setdefault("timeline", []).append({
            "timestamp": timestamp,
            "phase": "REPLAY",
            "event": f"[INFO] Replay completed. Status: {replay_res['status']}.",
            "severity": "INFO",
            "details": replay_res["result"]
        })
        
        log_success(f"Replay result: [bold]{replay_res['result']}[/bold] (Status: {replay_res['status']})")
        updated_count += 1

    # Persist updated report back to the JSON file
    if updated_count > 0:
        try:
            with open(args.report_file, "w") as f:
                json.dump(report, f, indent=2)
            log_success(f"Successfully updated replay history for {updated_count} finding(s) in {args.report_file}")
        except Exception as e:
            log_error(f"Failed to save updated report file: {e}")


def handle_plugin(args: argparse.Namespace) -> None:
    """Processes plugin subcommands."""
    from nextsploit.services.plugin_loader import PluginLoader
    from nextsploit.services.plugin_doctor import PluginDoctor

    loader = PluginLoader()
    loader.discover_and_load()

    if args.plugin_cmd == "list":
        log_info(f"Installed Plugins ({len(loader.loaded_manifests)}):")
        for pid, manifest in loader.loaded_manifests.items():
            print(f"- [bold cyan]{pid}[/bold cyan] ({manifest.get('name', 'N/A')}) - Severity: {manifest.get('severity', 'info')} - Policies: {manifest.get('policies', [])}")
            
    elif args.plugin_cmd == "info":
        if args.plugin_id in loader.loaded_manifests:
            print(json.dumps(loader.loaded_manifests[args.plugin_id], indent=2))
        else:
            log_error(f"Plugin ID '{args.plugin_id}' not loaded.")

    elif args.plugin_cmd == "verify":
        doctor = PluginDoctor()
        res = doctor.run_check(args.dir)
        manifest_res = res["checklist"]["Manifest"]
        if manifest_res["status"] == "PASS":
            log_success(f"✓ Manifest verification passed: {manifest_res['details']}")
        else:
            log_error(f"✗ Manifest verification failed: {manifest_res['details']}")

    elif args.plugin_cmd == "doctor":
        log_info(f"Starting thorough diagnostics on plugin directory: {args.dir}")
        doctor = PluginDoctor()
        res = doctor.run_check(args.dir)
        
        print("\n" + "="*50)
        print(" Plugin Doctor Checklist")
        print("="*50)
        
        for name, step in res["checklist"].items():
            icon = "✓" if step["status"] == "PASS" else "✗"
            color = "green" if step["status"] == "PASS" else "red"
            print(f"[{color}]{icon} {name:<20}[/{color}] - {step['details']} (Score: {step['score']}/{step['weight']})")
            
        print("="*50)
        h_score = res["health_score"]
        h_color = "green" if h_score >= 80 else "yellow" if h_score >= 50 else "red"
        print(f"Health Score: [{h_color}]{h_score}%[/{h_color}]")
        print("="*50)

    elif args.plugin_cmd in ("enable", "disable"):
        enable = args.plugin_cmd == "enable"
        config_path = "nextsploit/policies/active_plugins.json"
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        
        toggles = {}
        if os.path.exists(config_path):
            try:
                with open(config_path, "r") as f:
                    toggles = json.load(f)
            except Exception:
                pass
                
        toggles[args.plugin_id] = enable
        try:
            with open(config_path, "w") as f:
                json.dump(toggles, f, indent=2)
            log_success(f"Plugin '{args.plugin_id}' successfully {'enabled' if enable else 'disabled'}.")
        except Exception as e:
            log_error(f"Failed to update plugin toggle state: {e}")


def main() -> None:
    """Main CLI handler routing to active command handler."""
    args = parse_args()

    # Determine command routing
    cmd = args.command
    if not cmd:
        # Fallback to scan if legacy -t or -T options are populated
        if args.target or args.target_file:
            cmd = "scan"
        else:
            log_error("No subcommand or target specified. Run with -h/--help to see usage.")
            sys.exit(1)

    if cmd == "scan":
        handle_scan(args)
    elif cmd == "replay":
        handle_replay(args)
    elif cmd == "plugin":
        handle_plugin(args)


if __name__ == "__main__":
    main()
