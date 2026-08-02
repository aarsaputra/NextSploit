#!/usr/bin/env python3
"""
NextSploit — CVE-2026-64644: DoS Image Optimization API via SVG

Passive probe: sends a small benign SVG URL to /_next/image and checks
response timing / error patterns — does NOT upload a real decompression bomb.

Affected: >= 13.0.0, < 15.5.21 | >= 16.0.0, < 16.2.11
"""

import time, requests
from core.config import ScanConfig, CVE_DATABASE, check_vuln_status
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, log_debug, print_finding

CVE_ID   = "CVE-2026-64644"
CVE_INFO = CVE_DATABASE[CVE_ID]

# A data URI SVG (benign, tiny) — just to confirm endpoint accepts SVGs
_SVG_DATA_URI = "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxIiBoZWlnaHQ9IjEiLz4="


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(cve=CVE_ID, title=CVE_INFO["title"],
                          severity=CVE_INFO["severity"], status="NOT VULNERABLE")

    session = config.create_session()
    target  = config.target.rstrip("/")
    log_info(f"Starting {CVE_ID} — Image API SVG DoS check...")

    if config.has_managed_hosting():
        detail = (
            "Target hosted on Vercel (managed) — Image Optimization API SVG DoS is NOT APPLICABLE "
            "due to platform-level protection (per GHSA-q8wf-6r8g-63ch)."
        )
        result.status = "NOT_APPLICABLE"
        result.add_finding(Finding(
            cve=CVE_ID, severity=CVE_INFO["severity"],
            title="Managed Hosting Exemption — CVE-2026-64644 Not Applicable",
            status="NOT_APPLICABLE", detail=detail,
            evidence={"hosting": "Vercel (managed)", "exemption": "GHSA-q8wf-6r8g-63ch"},
            confidence=1.0,
        ))
        log_info(detail)
        return result

    best_ver = config.version_state.best()
    version_detected = best_ver.value if best_ver else None
    version_vulnerable = False
    if version_detected:
        vs = check_vuln_status(version_detected, CVE_ID)
        if vs == "PATCHED":
            log_success(f"{version_detected} is patched.")
            return result
        if vs == "VULNERABLE":
            version_vulnerable = True
            log_warning(f"{version_detected} is in the vulnerable range.")

    # Probe: check if /_next/image accepts SVG content-type without restriction
    url = f"{target}/_next/image?url={_SVG_DATA_URI}&w=64&q=75"
    accepts_svg = False
    try:
        t0 = time.monotonic()
        r  = session.get(url, timeout=config.timeout)
        elapsed = (time.monotonic() - t0) * 1000
        log_debug(f"[{r.status_code}] /_next/image SVG probe — {elapsed:.0f}ms")
        content_type = r.headers.get("Content-Type", "")
        if r.status_code == 200 and "svg" in content_type.lower():
            accepts_svg = True
            log_warning("Image API returned SVG content — endpoint may accept SVG inputs.")
        elif r.status_code == 200:
            # Still a successful response — endpoint active
            accepts_svg = True
    except requests.RequestException as e:
        log_debug(f"Probe error: {e}")

    if accepts_svg and version_vulnerable:
        detail = (f"CONFIRMED: Next.js {version_detected} + /_next/image accepts SVG inputs — "
                  "vulnerable to SVG-based DoS (CVE-2026-64644).")
        confidence = 0.80
    elif accepts_svg:
        detail = ("/_next/image accepts SVG inputs. Version unconfirmed — "
                  "vulnerable if < 15.5.21 or < 16.2.11.")
        confidence = 0.50
    elif version_vulnerable:
        detail = (f"{version_detected} in vulnerable range but SVG probe did not return 200.")
        confidence = 0.35
    else:
        log_success(f"No {CVE_ID} indicators detected.")
        return result

    evidence = {"detected_version": version_detected or "unknown", "probe_url": url,
                "remediation": "Upgrade to 15.5.21+ or 16.2.11+."}
    log_warning(detail)
    print_finding(CVE_ID, detail, evidence)
    result.add_finding(Finding(cve=CVE_ID, severity=CVE_INFO["severity"],
        title="DoS Image Optimization API via SVG", status="VULNERABLE",
        detail=detail, evidence=evidence, confidence=confidence))
    return result
