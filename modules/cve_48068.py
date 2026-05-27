#!/usr/bin/env python3
"""
NextSploit — CVE-2025-48068: Dev Server Source Code Exposure
"""

import requests
import re
from core.config import ScanConfig, CVE_DATABASE
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID = "CVE-2025-48068"
CVE_INFO = CVE_DATABASE.get(CVE_ID, {"title": "Dev Server Source Exposure", "severity": "LOW"})

def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO.get("title", "Dev Server Source Exposure"),
        severity=CVE_INFO.get("severity", "LOW"),
        status="NOT VULNERABLE"
    )
    
    session = config.create_session()
    target = config.target.rstrip("/")
    
    log_info(f"Starting {CVE_ID} scan...")

    try:
        # Check if it might be a dev server
        url = f"{target}/"
        headers = {
            "Origin": "http://attacker.example.com",
            "X-Forwarded-Host": "attacker.example.com"
        }
        
        log_debug("Checking if target might be a dev server...")
        r = session.get(url, headers=headers, timeout=config.timeout)
        
        is_dev_server = False
        if r.headers.get("x-nextjs-cache") == "MISS":
            is_dev_server = True
            log_debug("x-nextjs-cache: MISS detected. Might be a dev server.")
            
        # Common chunks to test
        chunks = [
            "/_next/static/chunks/main-app.js",
            "/_next/static/chunks/webpack.js",
            "/_next/static/chunks/app/layout.js",
            "/_next/static/chunks/app/page.js"
        ]
        
        for chunk in chunks:
            chunk_url = f"{target}{chunk}"
            log_debug(f"Testing chunk: {chunk_url}")
            
            req_headers = {
                "Origin": "http://evil.example.com",
                "Accept": "text/x-component, application/json",
                "Referer": "http://evil.example.com"
            }
            
            cr = session.get(chunk_url, headers=req_headers, timeout=config.timeout)
            
            if cr.status_code == 200 and "application/javascript" in cr.headers.get("Content-Type", ""):
                # Check for unminified code indicators
                content = cr.text
                if "webpackChunk_N_E" in content and (
                    "// WEBPACK FOOTER //" in content or
                    "__webpack_require__" in content or
                    "SourceMap" in content or
                    re.search(r'function\s*\([a-zA-Z0-9_,\s]*\)\s*\{', content) # Unminified functions
                ):
                    is_dev_server = True
                    detail = f"Dev Server Source Code Exposure at {chunk_url}"
                    log_warning(detail)
                    
                    # Scan for sensitive strings (basic)
                    sensitive_hits = []
                    if "password" in content.lower(): sensitive_hits.append("password")
                    if "api_key" in content.lower() or "apikey" in content.lower(): sensitive_hits.append("api_key")
                    if "secret" in content.lower(): sensitive_hits.append("secret")
                    
                    evidence = {
                        "endpoint": chunk_url,
                        "spoofed_origin": "http://evil.example.com",
                        "sensitive_keywords_found": sensitive_hits
                    }
                    
                    print_finding(CVE_ID, detail, evidence)
                    
                    result.add_finding(Finding(
                        cve=CVE_ID,
                        severity="MEDIUM" if sensitive_hits else CVE_INFO.get("severity", "LOW"),
                        title="Source Code Exposure Confirmed",
                        status="VULNERABLE",
                        detail=detail,
                        evidence=evidence,
                        confidence=0.85
                    ))
                    break
                    
    except requests.RequestException as e:
        result.error = str(e)
        
    if result.finding_count == 0:
        log_success("No Dev Server Source Exposure detected")

    return result
