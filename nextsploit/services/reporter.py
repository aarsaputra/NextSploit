"""
nextsploit/services/reporter.py — Reporter, Formatter, and Exporter implementations for Sprint 5A.
"""

import os
import json
import uuid
import time
import shutil
import hashlib
from typing import List, Dict, Any, Optional
from nextsploit.interfaces.reporter import IReporter, IFinding, IFormatter, IExporter


def get_sha256(text: str) -> str:
    """Helper to calculate SHA256 hex digest of a string."""
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class Finding:
    """
    Standard implementation of IFinding representing a structured vulnerability finding.
    Features nested sections, SHA256 evidence integrity hashes, and timeline events.
    """

    def __init__(
        self,
        id: str,
        title: str,
        severity: str,
        confidence: float,
        evidence: Dict[str, Any],
        category: str = "web",
        module: str = "generic",
        cve: str = "",
        cwe: str = "",
        owasp: str = "",
        remediation: str = "",
        request_raw: str = "",
        response_raw: str = "",
        timing: float = 0.0
    ):
        self.id = id
        self.title = title
        self.severity = severity
        self.confidence = confidence

        # 1. Metadata
        # Unique UUID suffix formatted as NSP-2026-<suffix>
        rand_suffix = str(uuid.uuid4())[:8].upper()
        self.metadata = {
          "uuid": f"NSP-2026-{rand_suffix}",
          "module": module,
          "category": category,
          "severity": severity,
          "confidence": confidence,
          "risk_score": 0.0,
          "cvss_score": 0.0,
          "priority_level": str(severity).upper()
        }

        # 2. Classifications
        self.classification = {
          "cve": cve,
          "cwe": cwe,
          "owasp": owasp
        }

        # 3. Evidence (with integrity check hashes)
        self.evidence = {
          "request": request_raw,
          "response": response_raw,
          "request_hash": get_sha256(request_raw),
          "response_hash": get_sha256(response_raw),
          "timing": timing,
          "extra": evidence
        }

        # 4. Replay Snapshots
        self.replay = {
          "last_replay": "",
          "result": "Not Replayed",
          "status": "pending",
          "snapshots": []
        }

        # 5. Timeline Events list
        self.timeline: List[Dict[str, str]] = []
        self.add_timeline_event("PLUGIN", "INFO", f"Vulnerability verification plugin '{id}' initialized.")

        # 6. Remediation Advice
        self.remediation = remediation

    def add_timeline_event(self, phase: str, severity: str, details: str) -> None:
        """Helper to append log events to the finding's timeline."""
        timestamp = time.strftime("%H:%M:%S", time.gmtime())
        self.timeline.append({
            "timestamp": timestamp,
            "phase": phase,
            "event": f"[{severity}] {details}",
            "severity": severity,
            "details": details
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "metadata": self.metadata,
            "classification": self.classification,
            "evidence": self.evidence,
            "replay": self.replay,
            "timeline": self.timeline,
            "remediation": self.remediation
        }


class ScanReporter(IReporter):
    """
    Centralized reporter tracking all discovered target findings.
    """

    def __init__(self):
        self._findings: List[IFinding] = []

    def add_finding(self, finding: IFinding) -> None:
        # Calculate risk scoring using the registered RiskEngine
        from nextsploit.core.container import container
        try:
            risk_engine = container.resolve("risk_engine")
            risk_score = risk_engine.calculate_risk_score(finding)
            cvss = risk_engine.calculate_cvss(finding)
            p_level = risk_engine.get_priority_level(risk_score)
            
            # Update Finding metadata
            if hasattr(finding, "metadata"):
                finding.metadata["risk_score"] = risk_score
                finding.metadata["cvss_score"] = cvss
                finding.metadata["priority_level"] = p_level
        except Exception:
            if hasattr(finding, "metadata"):
                finding.metadata["risk_score"] = 50.0
                finding.metadata["cvss_score"] = 5.0
                finding.metadata["priority_level"] = str(finding.severity).upper()

        self._findings.append(finding)

    def get_findings(self) -> List[IFinding]:
        return self._findings


class JSONFormatter(IFormatter):
    """Formats scan findings and context metadata into a Scan Manifest JSON."""

    def format(self, findings: List[IFinding], metadata: Dict[str, Any]) -> str:
        findings_list = []
        for f in findings:
            if hasattr(f, "to_dict"):
                findings_list.append(f.to_dict())
            else:
                findings_list.append({
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "metadata": getattr(f, "metadata", {}),
                    "classification": getattr(f, "classification", {}),
                    "evidence": getattr(f, "evidence", {}),
                    "replay": getattr(f, "replay", {}),
                    "timeline": getattr(f, "timeline", []),
                    "remediation": getattr(f, "remediation", "")
                })

        profile = metadata.get("profile", {})
        
        # Build Report Manifest structure
        report_manifest = {
            "schema_version": "1.0",
            "scan": {
                "id": f"SCAN-{time.strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
                "started_at": metadata.get("started_at", time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())),
                "finished_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "duration": round(metadata.get("duration", 0.0), 2)
            },
            "framework": {
                "version": metadata.get("version", "4.0.0-alpha"),
                "policy": metadata.get("policy", "safe")
            },
            "target": {
                "url": metadata.get("target", ""),
                "hostname": profile.get("hostname", ""),
                "ip": profile.get("ip", "")
            },
            "statistics": metadata.get("statistics", {}),
            "findings": findings_list
        }
        return json.dumps(report_manifest, indent=2)


class MarkdownFormatter(IFormatter):
    """Formats findings and target profile metadata into clean, readable Markdown."""

    def format(self, findings: List[IFinding], metadata: Dict[str, Any]) -> str:
        profile = metadata.get("profile", {})
        
        lines = []
        lines.append("# NextSploit Security Audit Report")
        lines.append("")
        lines.append("## Target Summary")
        lines.append(f"- **Target URL**: {metadata.get('target', 'N/A')}")
        lines.append(f"- **Hostname**: {profile.get('hostname', 'N/A')}")
        lines.append(f"- **IP Address**: {profile.get('ip', 'N/A')}")
        lines.append(f"- **Next.js Version**: {profile.get('framework_version', 'N/A')}")
        lines.append(f"- **Router Type**: {profile.get('router', 'N/A')}")
        lines.append(f"- **Hosting Provider**: {profile.get('hosting', 'N/A')}")
        lines.append(f"- **WAF/CDN**: {profile.get('waf', 'None detected')}")
        lines.append("")
        
        lines.append("## Target Capabilities")
        lines.append(f"- **Server Actions**: {'Enabled' if profile.get('server_actions') else 'Disabled'}")
        lines.append(f"- **React Server Components (RSC)**: {'Enabled' if profile.get('rsc') else 'Disabled'}")
        lines.append(f"- **Turbopack**: {'Enabled' if profile.get('turbopack') else 'Disabled'}")
        lines.append("")

        lines.append("## Vulnerability Findings")
        if not findings:
            lines.append("No security vulnerabilities were identified during this scan.")
        else:
            lines.append(f"Discovered **{len(findings)}** vulnerability finding(s):")
            lines.append("")
            for f in findings:
                meta = getattr(f, "metadata", {})
                cvss = meta.get("cvss_score", 5.0)
                r_score = meta.get("risk_score", 50.0)
                uuid_str = meta.get("uuid", "N/A")
                lines.append(f"### [{meta.get('priority_level', 'MEDIUM')}] {f.title} ({uuid_str})")
                lines.append(f"- **Calculated CVSS**: {cvss:.1f}")
                lines.append(f"- **Risk Score**: {r_score:.1f}/100")
                lines.append(f"- **Confidence**: {f.confidence:.2f}")
                lines.append(f"- **Remediation**: {getattr(f, 'remediation', 'N/A')}")
                lines.append("")
        
        return "\n".join(lines)


class HTMLFormatter(IFormatter):
    """Loads interactive template dashboard from templates/ and maps placeholder variables."""

    def format(self, findings: List[IFinding], metadata: Dict[str, Any]) -> str:
        # Load report.html from package templates folder
        current_dir = os.path.dirname(os.path.abspath(__file__))
        template_path = os.path.join(current_dir, "..", "templates", "report.html")
        
        try:
            with open(template_path, "r", encoding="utf-8") as f:
                template = f.read()
        except FileNotFoundError:
            # Fallback simple HTML layout if template not found
            template = "<html><body><h1>NextSploit Report fallback</h1><script>window.NEXTSPLOIT_FINDINGS = {{FINDINGS_JSON}};</script></body></html>"

        profile = metadata.get("profile", {})
        stats = metadata.get("statistics", {})
        
        # Build timeline HTML content
        timeline_items = []
        for f in findings:
            for ev in getattr(f, "timeline", []):
                sev_cls = "high" if ev.get("severity") in ("CRITICAL", "HIGH") else "medium"
                timeline_items.append(f"""
                <div class="timeline-item {sev_cls}">
                  <div class="timeline-dot"></div>
                  <div class="timeline-meta">{ev.get('timestamp', '')} - {ev.get('phase', '')}</div>
                  <div class="timeline-content"><strong>{ev.get('event', '')}</strong>: {ev.get('details', '')}</div>
                </div>
                """)
        timeline_html = "\n".join(timeline_items) if timeline_items else "<p>No timeline events recorded.</p>"

        # Convert findings to JSON dictionary list
        findings_list = []
        for f in findings:
            if hasattr(f, "to_dict"):
                findings_list.append(f.to_dict())
            else:
                findings_list.append({
                    "id": f.id,
                    "title": f.title,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "metadata": getattr(f, "metadata", {}),
                    "classification": getattr(f, "classification", {}),
                    "evidence": getattr(f, "evidence", {}),
                    "replay": getattr(f, "replay", {}),
                    "timeline": getattr(f, "timeline", []),
                    "remediation": getattr(f, "remediation", "")
                })

        # Replace placeholders
        replacements = {
            "{{SCAN_ID}}": f"SCAN-{time.strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}",
            "{{TARGET_URL}}": metadata.get("target", "N/A"),
            "{{SCAN_DATE}}": time.strftime("%Y-%m-%d %H:%M:%S GMT", time.gmtime()),
            "{{TOTAL_FINDINGS}}": str(len(findings)),
            "{{POLICY_NAME}}": metadata.get("policy", "safe"),
            "{{SCAN_DURATION}}": f"{metadata.get('duration', 0.0):.2f}",
            "{{HOSTNAME}}": profile.get("hostname", "N/A"),
            "{{IP_ADDRESS}}": profile.get("ip", "N/A"),
            "{{NEXTJS_VERSION}}": profile.get("framework_version", "N/A"),
            "{{ROUTER_TYPE}}": profile.get("router", "N/A"),
            "{{WAF_CDN}}": profile.get("waf", "None detected"),
            "{{HOSTING}}": profile.get("hosting", "N/A"),
            "{{CAP_SERVER_ACTIONS}}": "enabled" if profile.get("server_actions") else "disabled",
            "{{CAP_RSC}}": "enabled" if profile.get("rsc") else "disabled",
            "{{CAP_TURBOPACK}}": "enabled" if profile.get("turbopack") else "disabled",
            "{{REQ_TOTAL}}": str(stats.get("total_requests", 0)),
            "{{REQ_RECEIVED}}": str(stats.get("responses_received", 0)),
            "{{REQ_WAF}}": str(stats.get("waf_blocks", 0)),
            "{{REQ_FAILED}}": str(stats.get("failed_requests", 0)),
            "{{REQ_LATENCY}}": str(stats.get("average_latency_ms", 0.0)),
            "{{REQ_SUCCESS}}": str(stats.get("success_rate_percent", 100.0)),
            "{{TIMELINE_ITEMS}}": timeline_html,
            "{{FINDINGS_JSON}}": json.dumps(findings_list)
        }

        output = template
        for k, v in replacements.items():
            output = output.replace(k, str(v) if v is not None else "N/A")
        return output


class SARIFFormatter(IFormatter):
    """Formats findings into the OASIS SARIF v2.1.0 standard."""

    def format(self, findings: List[IFinding], metadata: Dict[str, Any]) -> str:
        sarif_results = []
        sarif_rules = []
        
        for f in findings:
            meta = getattr(f, "metadata", {})
            classif = getattr(f, "classification", {})
            
            # Map severity to SARIF levels: error, warning, note
            sev = str(f.severity).lower()
            level = "warning"
            if sev in ("critical", "high"):
                level = "error"
            elif sev == "low":
                level = "note"
            elif sev == "info":
                level = "note"

            sarif_rules.append({
                "id": f.id,
                "shortDescription": {
                    "text": f.title
                },
                "properties": {
                    "cwe": classif.get("cwe", ""),
                    "owasp": classif.get("owasp", "")
                }
            })

            sarif_results.append({
                "ruleId": f.id,
                "level": level,
                "message": {
                    "text": f"{f.title} - Severity Priority: {meta.get('priority_level', 'MEDIUM')}. Risk Score: {meta.get('risk_score', 0.0)}/100."
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": metadata.get("target", "")
                            }
                        }
                    }
                ],
                "properties": {
                    "uuid": meta.get("uuid", ""),
                    "cvss": meta.get("cvss_score", 5.0),
                    "confidence": f.confidence,
                    "remediation": getattr(f, "remediation", "")
                }
            })

        sarif_doc = {
            "$schema": "https://schemastore.org/json/schemas/sarif-2.1.0-rtm.5.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "NextSploit",
                            "semanticVersion": "4.0.0-alpha",
                            "rules": sarif_rules
                        }
                    },
                    "results": sarif_results
                }
            ]
        }
        return json.dumps(sarif_doc, indent=2)


class FileExporter(IExporter):
    """Saves formatted scan report to the local file system and copies static templates if HTML."""

    def export(self, formatted_content: str, destination: str) -> None:
        with open(destination, "w", encoding="utf-8") as f:
            f.write(formatted_content)
        
        # If exporting to HTML, copy style.css and script.js next to the report HTML file
        if destination.endswith(".html"):
            dest_dir = os.path.dirname(os.path.abspath(destination))
            current_dir = os.path.dirname(os.path.abspath(__file__))
            templates_dir = os.path.join(current_dir, "..", "templates")
            
            try:
                shutil.copy(
                    os.path.join(templates_dir, "style.css"),
                    os.path.join(dest_dir, "style.css")
                )
                shutil.copy(
                    os.path.join(templates_dir, "script.js"),
                    os.path.join(dest_dir, "script.js")
                )
            except Exception:
                # Swallow if template files missing during unit testing
                pass
