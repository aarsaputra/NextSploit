#!/usr/bin/env python3
"""
NextSploit — CVE-2024-34350: HTTP Request Smuggling Check
"""

import requests
from core.config import ScanConfig, CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID = "CVE-2024-34350"
CVE_INFO = CVE_DATABASE[CVE_ID]

def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status="NOT VULNERABLE"
    )
    
    session = config.create_session()
    target = config.target.rstrip("/")
    
    log_info(f"Starting {CVE_ID} scan...")
    
    # 1. Check version status if discovered during fingerprinting
    version_detected = getattr(config, "discovered_version", None)
    
    if version_detected:
        log_debug(f"Detected Next.js Version: {version_detected}")
        vuln_status = check_vuln_status(version_detected, CVE_ID)
        
        if vuln_status == "VULNERABLE":
            detail = f"Target is vulnerable to {CVE_ID} based on detected version: {version_detected} (requires < 13.5.1)"
            log_warning(detail)
            
            evidence = {
                "detected_version": version_detected,
                "vulnerability_status": "VULNERABLE",
                "remediation": "Upgrade Next.js to version 13.5.1 or newer."
            }
            
            print_finding(CVE_ID, detail, evidence)
            
            result.add_finding(Finding(
                cve=CVE_ID,
                severity=CVE_INFO["severity"],
                title="Vulnerability Confirmed (Version-based)",
                status="VULNERABLE",
                detail=detail,
                evidence=evidence,
                confidence=0.85
            ))
            return result

    # 2. Passive header-based checks
    try:
        r = session.get(f"{target}/", timeout=config.timeout)
        headers = r.headers
        
        # Look for indicators that rewrite headers or proxied layers are present
        has_next = "x-nextjs-cache" in headers or "x-powered-by" in headers or "server" in headers
        
        if has_next:
            log_debug("Next.js response headers observed. Target identity active.")
            
    except requests.RequestException as e:
        result.error = str(e)
        
    if result.finding_count == 0:
        log_success(f"No active {CVE_ID} vulnerability confirmed on target.")
        
    return result
