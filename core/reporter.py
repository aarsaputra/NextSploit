#!/usr/bin/env python3
"""
NextSploit — Report Generator (JSON / HTML / TXT)
"""

import json
import os
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Optional

from core.output import console, log_info, log_success, log_error


# ─── Data Classes ────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single vulnerability finding."""
    cve: str
    severity: str
    title: str
    status: str  # VULNERABLE, NOT VULNERABLE, ERROR
    detail: str = ""
    evidence: dict = field(default_factory=dict)
    confidence: float = 0.5  # 0.0 - 1.0

    def compute_confidence(self) -> float:
        score = self.confidence
        if self.severity == "CRITICAL": score += 0.2
        elif self.severity == "HIGH":   score += 0.1
        if self.status == "VULNERABLE": score += 0.2
        if self.evidence.get("baseline_confirmed"): score += 0.1
        return min(1.0, score)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["computed_confidence"] = self.compute_confidence()
        return d



@dataclass
class ModuleResult:
    """Result from a single scanner module."""
    cve: str
    title: str
    severity: str
    status: str  # VULNERABLE, NOT VULNERABLE, ERROR
    findings: list = field(default_factory=list)
    finding_count: int = 0
    error: str = ""

    def add_finding(self, finding: Finding):
        self.findings.append(finding)
        self.finding_count = len(self.findings)
        if finding.status == "VULNERABLE":
            self.status = "VULNERABLE"

    def to_dict(self) -> dict:
        return {
            "cve": self.cve,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "finding_count": self.finding_count,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }


# ─── Scan Report ─────────────────────────────────────────────────────────────

class ScanReport:
    """Collects all scan results and exports them."""

    def __init__(self, target: str):
        self.target = target
        self.scan_date = datetime.now(timezone.utc).isoformat()
        self.nextjs_version: Optional[str] = None
        self.build_id: Optional[str] = None
        self.vuln_matrix: list = []
        self.module_results: list = []

    def add_result(self, result: ModuleResult):
        self.module_results.append(result)

    def to_dict(self) -> dict:
        total = len(self.module_results)
        vuln = sum(1 for r in self.module_results if r.status == "VULNERABLE")
        safe = sum(1 for r in self.module_results if r.status == "NOT VULNERABLE")
        errors = sum(1 for r in self.module_results if r.status == "ERROR")

        return {
            "target": self.target,
            "scan_date": self.scan_date,
            "nextjs_version": self.nextjs_version,
            "build_id": self.build_id,
            "vulnerability_matrix": self.vuln_matrix,
            "module_results": [r.to_dict() for r in self.module_results],
            "summary": {
                "total_modules": total,
                "vulnerable": vuln,
                "not_vulnerable": safe,
                "errors": errors,
                "total_findings": sum(r.finding_count for r in self.module_results),
            },
        }

    def get_summary_rows(self) -> list:
        """Get summary data for the Rich table."""
        rows = []
        for r in self.module_results:
            rows.append({
                "cve": r.cve,
                "title": r.title,
                "severity": r.severity,
                "status": r.status,
                "finding_count": r.finding_count,
            })
        return rows

    # ─── Exporters ───────────────────────────────────────────────────────

    def save(self, filepath: str):
        """Auto-detect format from extension and save."""
        os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", exist_ok=True)

        ext = os.path.splitext(filepath)[1].lower()
        if ext == ".json":
            self._save_json(filepath)
        elif ext == ".html":
            self._save_html(filepath)
        elif ext == ".txt":
            self._save_txt(filepath)
        else:
            # Default to JSON
            filepath = filepath + ".json"
            self._save_json(filepath)

        log_success(f"Report saved to [bold]{filepath}[/bold]")

    def _save_json(self, filepath: str):
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    def _save_txt(self, filepath: str):
        data = self.to_dict()
        lines = []
        lines.append("=" * 70)
        lines.append("  NEXTSPLOIT SCAN REPORT")
        lines.append("=" * 70)
        lines.append(f"  Target       : {data['target']}")
        lines.append(f"  Scan Date    : {data['scan_date']}")
        lines.append(f"  Next.js Ver  : {data['nextjs_version'] or 'Unknown'}")
        lines.append(f"  Build ID     : {data['build_id'] or 'Unknown'}")
        lines.append("=" * 70)
        lines.append("")

        # Vulnerability Matrix
        if data.get("vulnerability_matrix"):
            lines.append("─" * 70)
            lines.append("  VULNERABILITY MATRIX")
            lines.append("─" * 70)
            lines.append(f"  {'CVE':<20} {'Type':<20} {'Fix':<10} {'Status':<16}")
            lines.append("  " + "-" * 66)
            for v in data["vulnerability_matrix"]:
                lines.append(f"  {v['cve']:<20} {v['type']:<20} {v['fix_version']:<10} {v['status']:<16}")
            lines.append("")

        # Module Results
        for mod in data["module_results"]:
            lines.append("─" * 70)
            lines.append(f"  [{mod['severity']}] {mod['cve']} — {mod['title']}")
            lines.append(f"  Status: {mod['status']} | Findings: {mod['finding_count']}")
            lines.append("─" * 70)

            if mod.get("error"):
                lines.append(f"  Error: {mod['error']}")

            for finding in mod.get("findings", []):
                lines.append(f"  ▸ [{finding['severity']}] {finding['detail']}")
                if finding.get("evidence"):
                    for k, v in finding["evidence"].items():
                        lines.append(f"    {k}: {v}")
                lines.append("")

            lines.append("")

        # Summary
        summary = data["summary"]
        lines.append("=" * 70)
        lines.append("  SUMMARY")
        lines.append("=" * 70)
        lines.append(f"  Total Modules   : {summary['total_modules']}")
        lines.append(f"  Vulnerable      : {summary['vulnerable']}")
        lines.append(f"  Not Vulnerable  : {summary['not_vulnerable']}")
        lines.append(f"  Errors          : {summary['errors']}")
        lines.append(f"  Total Findings  : {summary['total_findings']}")
        lines.append("=" * 70)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _save_html(self, filepath: str):
        data = self.to_dict()
        summary = data["summary"]

        # Build vulnerability matrix rows
        matrix_rows = ""
        for v in data.get("vulnerability_matrix", []):
            status_class = "vuln" if "VULNERABLE" in v["status"] else "safe"
            matrix_rows += f"""
            <tr>
                <td><code>{v['cve']}</code></td>
                <td>{v['type']}</td>
                <td><code>{v['fix_version']}</code></td>
                <td class="{status_class}">{v['status']}</td>
            </tr>"""

        # Build module result cards
        module_cards = ""
        for mod in data["module_results"]:
            sev_class = mod["severity"].lower()
            status_class = "vuln" if mod["status"] == "VULNERABLE" else "safe"

            findings_html = ""
            for finding in mod.get("findings", []):
                evidence_html = ""
                if finding.get("evidence"):
                    evidence_items = "".join(
                        f"<li><strong>{k}:</strong> <code>{v}</code></li>"
                        for k, v in finding["evidence"].items()
                    )
                    evidence_html = f"<ul class='evidence'>{evidence_items}</ul>"

                findings_html += f"""
                <div class="finding">
                    <span class="finding-badge {finding['severity'].lower()}">{finding['severity']}</span>
                    <span>{finding['detail']}</span>
                    {evidence_html}
                </div>"""

            module_cards += f"""
            <div class="module-card">
                <div class="module-header">
                    <span class="severity-badge {sev_class}">{mod['severity']}</span>
                    <strong>{mod['cve']}</strong> — {mod['title']}
                    <span class="status-badge {status_class}">{mod['status']}</span>
                </div>
                <div class="module-body">
                    <p>Findings: <strong>{mod['finding_count']}</strong></p>
                    {findings_html}
                    {f'<p class="error">Error: {mod["error"]}</p>' if mod.get("error") else ''}
                </div>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NextSploit Report — {data['target']}</title>
    <style>
        :root {{
            --bg: #0d1117; --surface: #161b22; --border: #30363d;
            --text: #e6edf3; --text-dim: #8b949e; --accent: #58a6ff;
            --red: #f85149; --green: #3fb950; --yellow: #d29922; --orange: #db6d28;
        }}
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
            background: var(--bg); color: var(--text); line-height: 1.6;
            padding: 2rem; max-width: 1100px; margin: 0 auto;
        }}
        h1 {{ color: var(--red); font-size: 1.8rem; margin-bottom: 0.5rem; }}
        h2 {{ color: var(--accent); font-size: 1.3rem; margin: 1.5rem 0 0.8rem; border-bottom: 1px solid var(--border); padding-bottom: 0.5rem; }}
        .meta {{ color: var(--text-dim); margin-bottom: 1rem; }}
        .meta span {{ margin-right: 2rem; }}
        .meta code {{ color: var(--accent); background: var(--surface); padding: 2px 6px; border-radius: 4px; }}

        /* Summary Cards */
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 1rem; margin: 1rem 0; }}
        .summary-card {{
            background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
            padding: 1rem; text-align: center;
        }}
        .summary-card .number {{ font-size: 2rem; font-weight: bold; }}
        .summary-card .label {{ color: var(--text-dim); font-size: 0.85rem; }}
        .summary-card.vuln .number {{ color: var(--red); }}
        .summary-card.safe .number {{ color: var(--green); }}

        /* Tables */
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
        th, td {{ padding: 0.6rem 1rem; text-align: left; border: 1px solid var(--border); }}
        th {{ background: var(--surface); color: var(--accent); font-weight: 600; }}
        td.vuln {{ color: var(--red); font-weight: bold; }}
        td.safe {{ color: var(--green); font-weight: bold; }}

        /* Module Cards */
        .module-card {{
            background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
            margin: 1rem 0; overflow: hidden;
        }}
        .module-header {{
            padding: 0.8rem 1rem; border-bottom: 1px solid var(--border);
            display: flex; align-items: center; gap: 0.8rem; flex-wrap: wrap;
        }}
        .module-body {{ padding: 1rem; }}

        /* Badges */
        .severity-badge, .status-badge {{
            padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: bold;
            text-transform: uppercase;
        }}
        .severity-badge.critical {{ background: rgba(248,81,73,0.2); color: var(--red); }}
        .severity-badge.high {{ background: rgba(210,153,34,0.2); color: var(--yellow); }}
        .severity-badge.medium {{ background: rgba(219,109,40,0.2); color: var(--orange); }}
        .status-badge.vuln {{ background: rgba(248,81,73,0.2); color: var(--red); }}
        .status-badge.safe {{ background: rgba(63,185,80,0.2); color: var(--green); }}
        .status-badge {{ margin-left: auto; }}

        /* Findings */
        .finding {{
            padding: 0.5rem 0.8rem; margin: 0.5rem 0; border-left: 3px solid var(--red);
            background: rgba(248,81,73,0.05); border-radius: 0 4px 4px 0;
        }}
        .finding-badge {{
            padding: 1px 6px; border-radius: 4px; font-size: 0.7rem; font-weight: bold;
            margin-right: 0.5rem;
        }}
        .finding-badge.critical {{ background: var(--red); color: #fff; }}
        .finding-badge.high {{ background: var(--yellow); color: #000; }}
        .evidence {{ margin: 0.3rem 0 0 2rem; color: var(--text-dim); font-size: 0.85rem; }}
        .evidence code {{ background: var(--bg); padding: 1px 4px; border-radius: 3px; }}
        .error {{ color: var(--red); font-style: italic; }}

        footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--text-dim); font-size: 0.85rem; text-align: center; }}
    </style>
</head>
<body>
    <h1>🔴 NextSploit Scan Report</h1>
    <div class="meta">
        <span>Target: <code>{data['target']}</code></span>
        <span>Date: <code>{data['scan_date']}</code></span><br>
        <span>Next.js: <code>{data['nextjs_version'] or 'Unknown'}</code></span>
        <span>Build ID: <code>{data['build_id'] or 'Unknown'}</code></span>
    </div>

    <h2>📊 Summary</h2>
    <div class="summary-grid">
        <div class="summary-card"><div class="number">{summary['total_modules']}</div><div class="label">Modules Run</div></div>
        <div class="summary-card vuln"><div class="number">{summary['vulnerable']}</div><div class="label">Vulnerable</div></div>
        <div class="summary-card safe"><div class="number">{summary['not_vulnerable']}</div><div class="label">Not Vulnerable</div></div>
        <div class="summary-card"><div class="number">{summary['total_findings']}</div><div class="label">Total Findings</div></div>
    </div>

    <h2>🎯 Vulnerability Matrix</h2>
    <table>
        <thead><tr><th>CVE</th><th>Type</th><th>Fix Version</th><th>Status</th></tr></thead>
        <tbody>{matrix_rows}</tbody>
    </table>

    <h2>🔍 Detailed Results</h2>
    {module_cards}

    <footer>
        Generated by NextSploit v1.0.0 — Next.js Vulnerability Scanner & Exploit Tool
    </footer>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
