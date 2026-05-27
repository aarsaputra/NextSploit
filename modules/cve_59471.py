#!/usr/bin/env python3
"""
NextSploit — CVE-2025-59471: Image Optimizer DoS Check
"""

import requests
from core.config import ScanConfig, CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID = "CVE-2025-59471"
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
    
    # 1. Version check
    version_detected = getattr(config, "discovered_version", None)
    
    if version_detected:
        log_debug(f"Detected Next.js Version: {version_detected}")
        vuln_status = check_vuln_status(version_detected, CVE_ID)
        
        if vuln_status == "VULNERABLE":
            detail = f"Target is vulnerable to {CVE_ID} based on detected version: {version_detected} (requires < 15.5.10)"
            log_warning(detail)
            
            evidence = {
                "detected_version": version_detected,
                "vulnerability_status": "VULNERABLE",
                "remediation": "Upgrade Next.js to version 15.5.10 or newer."
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

    # 2. Passive endpoint verification
    try:
        # Check if the /_next/image endpoint is active
        url = f"{target}/_next/image?url=%2Ffavicon.ico&w=64&q=75"
        log_debug(f"Verifying Image Optimizer endpoint: {url}")
        
        r = session.get(url, timeout=config.timeout)
        
        # Next.js Image Optimizer returns 400 for bad parameters but confirming the route is active
        # Or 200 if the favicon exists and optimization works
        if r.status_code in [200, 400]:
            log_debug(f"Image Optimization endpoint is active (HTTP status: {r.status_code})")
            
    except requests.RequestException as e:
        result.error = str(e)
        
    if result.finding_count == 0:
        log_success(f"No active {CVE_ID} vulnerability confirmed on target.")
        
    return result
