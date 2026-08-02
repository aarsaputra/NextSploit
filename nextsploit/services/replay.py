"""
nextsploit/services/replay.py — Replay Engine for strict/smart validation and differential analysis.
"""

import time
import requests
import difflib
from typing import Dict, Any, List, Optional
from nextsploit.services.resource import ResourceManagerSession
from nextsploit.services.event_bus import EventBus


class ReplayEngine:
    """
    Executes request verification replays using STRICT, SMART, or DIFF mode.
    Loads finding evidence, builds the replayed HTTP request, executes it,
    and returns a structured replay result snapshot.
    """

    def __init__(self, event_bus: Optional[EventBus] = None):
        self.event_bus = event_bus or EventBus()

    def replay_finding(
        self,
        finding_data: Dict[str, Any],
        mode: str = "SMART"
    ) -> Dict[str, Any]:
        """
        Replays a single finding.
        Returns a dict indicating vulnerability status, last replay time, and a structural diff.
        """
        evidence = finding_data.get("evidence", {}) or {}
        orig_req = evidence.get("request", "") or ""
        orig_resp = evidence.get("response", "") or ""

        # Parse request info
        method = "GET"
        url = ""
        headers = {}
        body = ""

        # Simple request line parsing
        req_lines = orig_req.splitlines()
        if req_lines:
            parts = req_lines[0].split()
            if len(parts) >= 2:
                method = parts[0]
                url = parts[1]
            
            # Parse headers and body
            in_body = False
            body_parts = []
            for line in req_lines[1:]:
                if not line.strip() and not in_body:
                    in_body = True
                    continue
                if in_body:
                    body_parts.append(line)
                else:
                    h_parts = line.split(":", 1)
                    if len(h_parts) == 2:
                        headers[h_parts[0].strip()] = h_parts[1].strip()
            body = "\n".join(body_parts)

        # Skip if no URL found
        if not url:
            return {
                "status": "error",
                "result": "Could not parse original request URL.",
                "last_replay": time.strftime("%Y-%m-%d %H:%M:%S GMT", time.gmtime()),
                "snapshots": []
            }

        # Initialize session
        session = ResourceManagerSession(event_bus=self.event_bus, rate_limit=5)
        
        # Execute the HTTP request
        try:
            start_time = time.monotonic()
            r = session.request(method, url, headers=headers, data=body if body else None, timeout=10)
            elapsed = time.monotonic() - start_time
            
            # Format replayed response text
            replayed_headers_str = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            replayed_response = f"HTTP/{r.raw.version} {r.status_code} {r.reason}\n{replayed_headers_str}\n\n{r.text}"
            
            # Run comparison analysis
            analysis = self._compare(orig_resp, replayed_response, mode)
            
            # Determine overall vulnerability status
            # If status codes match and content is verified, it is still vulnerable
            is_vulnerable = analysis["is_match"]
            
            result_str = "Verified Vulnerable" if is_vulnerable else "Patched / Not Reproducible"
            status_str = "vulnerable" if is_vulnerable else "patched"

            snapshot = {
                "mode": mode,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S GMT", time.gmtime()),
                "duration": elapsed,
                "original": orig_resp[:1000], # truncate to preserve file size
                "replay": replayed_response[:1000],
                "diff": analysis["diff"]
            }

            return {
                "status": status_str,
                "result": result_str,
                "last_replay": time.strftime("%Y-%m-%d %H:%M:%S GMT", time.gmtime()),
                "snapshots": [snapshot]
            }

        except Exception as e:
            return {
                "status": "error",
                "result": f"Connection failure during replay: {e}",
                "last_replay": time.strftime("%Y-%m-%d %H:%M:%S GMT", time.gmtime()),
                "snapshots": []
            }

    def _compare(self, original: str, replayed: str, mode: str) -> Dict[str, Any]:
        """Compares original response with replayed response using STRICT, SMART, or DIFF mode."""
        orig_lines = original.splitlines()
        repl_lines = replayed.splitlines()

        # Extract status code
        orig_status = self._get_status(orig_lines)
        repl_status = self._get_status(repl_lines)

        if mode == "STRICT":
            is_match = (orig_status == repl_status) and (original == replayed)
            diff_text = "" if is_match else "\n".join(difflib.unified_diff(orig_lines, repl_lines))
            return {
                "is_match": is_match,
                "diff": {
                    "status": f"{orig_status} -> {repl_status}",
                    "details": diff_text
                }
            }

        elif mode == "SMART":
            # Smart comparison: ignore dates, cookie variations, csrf tokens, nonces
            san_orig = self._sanitize_for_smart_mode(orig_lines)
            san_repl = self._sanitize_for_smart_mode(repl_lines)
            
            is_match = (orig_status == repl_status) and (san_orig == san_repl)
            diff_text = "" if is_match else "\n".join(difflib.unified_diff(san_orig, san_repl))
            return {
                "is_match": is_match,
                "diff": {
                    "status": f"{orig_status} -> {repl_status}",
                    "details": diff_text
                }
            }

        else:  # DIFF Mode
            # Returns a structural dictionary detailing differences
            is_match = orig_status == repl_status
            diff_lines = list(difflib.unified_diff(orig_lines, repl_lines))
            
            added_headers = []
            removed_headers = []
            body_changes = []

            for line in diff_lines:
                if line.startswith("+") and not line.startswith("+++"):
                    val = line[1:]
                    if ":" in val:
                        added_headers.append(val.strip())
                    else:
                        body_changes.append(f"+ {val.strip()}")
                elif line.startswith("-") and not line.startswith("---"):
                    val = line[1:]
                    if ":" in val:
                        removed_headers.append(val.strip())
                    else:
                        body_changes.append(f"- {val.strip()}")

            return {
                "is_match": is_match,
                "diff": {
                    "status": {
                        "original": orig_status,
                        "replayed": repl_status,
                        "changed": orig_status != repl_status
                    },
                    "headers": {
                        "added": added_headers,
                        "removed": removed_headers
                    },
                    "body": body_changes[:50] # Limit to top 50 lines of diff
                }
            }

    def _get_status(self, lines: List[str]) -> int:
        if not lines:
            return 0
        parts = lines[0].split()
        if len(parts) >= 2:
            try:
                return int(parts[1])
            except ValueError:
                return 0
        return 0

    def _sanitize_for_smart_mode(self, lines: List[str]) -> List[str] | str:
        """Strips ephemeral and variable fields like date, nonce, cookie, request-id, CSRF."""
        sanitized = []
        ignore_headers = {"date", "cookie", "set-cookie", "x-request-id", "x-runtime", "x-csrf-token", "cf-ray", "server"}
        
        in_body = False
        for line in lines:
            if not line.strip() and not in_body:
                in_body = True
                sanitized.append("")
                continue
            
            if not in_body:
                # Parse header
                parts = line.split(":", 1)
                if len(parts) == 2:
                    k = parts[0].strip().lower()
                    if k in ignore_headers:
                        continue
                sanitized.append(line)
            else:
                # Strip typical variable nonce/timestamp keywords in json/html body lines
                line_lower = line.lower()
                if "nonce" in line_lower or "csrf" in line_lower or "token" in line_lower or "timestamp" in line_lower:
                    # Replace variable line content with placeholder to ignore variations
                    sanitized.append("[variable-nonce-or-token-line-ignored]")
                else:
                    sanitized.append(line)
        return sanitized
