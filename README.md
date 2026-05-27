# 🚀 NextSploit v2.0 — Next.js Security Auditing Framework

NextSploit is a modular penetration testing automation framework specifically designed to scan, detect, and analyze vulnerabilities in **Next.js** web applications.

This framework helps *Security Engineers* verify application resilience and assists *Software Developers* in identifying and remediating security flaws before deploying code to production.

---

## 🎯 Table of Contents
1. [Prerequisites & Installation](#-prerequisites--installation)
2. [Key v2.0 Features](#-key-v20-features)
3. [Complete CLI Parameters](#%EF%B8%8F-complete-cli-parameters)
4. [Project Architecture & Scanning Workflow](#-project-architecture--scanning-workflow)
5. [Integration & Custom Module Development Guide (For Programmers)](#-integration--custom-module-development-guide-for-programmers)
6. [Remediation & Mitigation Guide (For Users/Developers)](#-remediation--mitigation-guide-for-usersdevelopers)
7. [Troubleshooting](#-troubleshooting)
8. [Disclaimer](#%EF%B8%8F-disclaimer)

---

## 📋 Prerequisites & Installation

### System Requirements
*   **Python**: Version `3.8` or newer.
*   **Network Connectivity**: Required for active scanning modules (unless analyzing local test beds offline).

### Installing Dependencies
NextSploit relies on standard third-party libraries: `requests` for robust HTTP communications and `rich` for terminal interface styling. Install them using:

```bash
pip3 install -r requirements.txt
```

*If `requirements.txt` is not present, install them manually:*
```bash
pip3 install requests rich urllib3
```

---

## ✨ Key v2.0 Features

NextSploit v2.0 introduces powerful enhancements focused on **High Accuracy** and **Extensibility**:

1.  **Baseline-Driven Scanning**: Eliminates false positives by collecting baseline hashes and sizes for every endpoint before testing. It only flags anomalies when a request's response actively deviates from the baseline.
2.  **Context-Aware Keywords**: Smart parsing that strips third-party analytics and script tags (such as Google Tag Manager scripts) before looking for credential leaks.
3.  **Global Context Sharing**: Crucial assets discovered during fingerprinting—like *Build IDs* or active *Server Action IDs*—are dynamically shared with attack modules.
4.  **Cutting-edge CVE Modules**:
    *   **CVE-2025-66478 (React2Shell)**: Analyzes React Server Components (RSC) Flight Protocol deserialization bugs (CVSS 10.0).
    *   **CVE-2024-34351**: Passive validation of SSRF vectors in Server Action redirect paths using Host Header manipulation.

---

## ⚙️ Complete CLI Parameters

NextSploit provides a highly flexible Command-Line Interface (CLI):

| Parameter | Alternative | Description | Example Usage |
| :--- | :--- | :--- | :--- |
| `-t` | `--target` | Target URL of the Next.js app (Required, except for `--list-modules`) | `-t https://target.com` |
| `--fingerprint` | *None* | Runs fingerprinting probes only (version, Build ID, Action IDs) | `--fingerprint` |
| `--cve` | *None* | Executes specific scan modules by ID (comma-separated list) | `--cve 57822,34351` |
| `--all` | *None* | Runs all registered scanning modules | `--all` |
| `-o` | `--output` | Saves the report (automatically infers format: `.json`, `.html`, `.txt`) | `-o reports/scan.html` |
| `-v` | *None* | Verbose mode (displays rich analytical debugging logs) | `-v` |
| `-vv` | *None* | Extra Verbose mode (prints entire HTTP payloads and stack trace outputs) | `-vv` |
| `--browser` | *None* | **[AnonKryptiQuz integration]** After a CRITICAL CVE-2025-29927 bypass is confirmed, automatically open Chrome with the bypass header pre-configured for live visual verification. Requires `selenium` + `chromedriver`. | `--cve 29927 --browser` |
| `--list-modules`| *None* | Renders a table of all registered scanning modules | `--list-modules` |

---

## 📂 Project Architecture & Scanning Workflow

The modular design ensures rapid maintenance and updates:

```text
NextSploit/
├── nextsploit.py            # CLI Entrypoint & scan orchestrator
├── core/
│   ├── config.py            # Shared CVE database & customized requests session
│   ├── output.py            # Rich logging formatting functions
│   └── reporter.py          # Multiformat report exporter (JSON, HTML, TXT)
└── modules/
    ├── __init__.py          # Module registry and function mapping
    ├── fingerprint.py       # Tech stack identification & build asset crawler
    ├── cve_57822.py         # Baseline-safe SSRF Header Scanner
    ├── cve_34351.py         # Server Action Host-Header SSRF validator
    ├── cve_66478.py         # React2Shell RSC Deserialization scanner (Passive)
    ├── cve_29927.py         # Middleware Authorization Bypass + Browser Exploit Chain
    ├── cve_46982.py         # Cache Poisoning / Stored XSS Scanner
    ├── cve_56332.py         # Pathname Middleware Bypass Scanner
    ├── cve_48068.py         # Dev Server Source Exposure Scanner
    └── rsc_attack.py        # Active RSC endpoint & Proto Pollution scanner
```

> **Browser Exploit Engine** (`cve_29927.py → open_bypassed_page()`): When `--browser` is passed and a **CRITICAL** middleware bypass is detected, NextSploit automatically chains into the browser exploit engine ported from **[AnonKryptiQuz/NextSploit](https://github.com/AnonKryptiQuz/NextSploit)**. Chrome is launched with the `x-middleware-subrequest` header pre-injected via Selenium CDP, allowing live visual verification of the bypass.

### Orchestrator Workflow (`nextsploit.py`):
1.  **Initialization**: Sanitizes the target URL and creates an HTTP session with customizable options.
2.  **Fingerprinting (Mandatory)**: Collects Next.js version metadata, asset structures, and potential Action IDs, storing them in the global `ScanConfig` object.
3.  **Module Selection**: Filters modules based on `--cve` or `--all` flags.
4.  **Dynamic Invocation**: Imports and fires the target modules using `importlib` and calls their `scan(config)` handler.
5.  **Reporting**: Combines all findings (`Finding`) inside a `ScanReport` class and exports to the requested format.

---

## 💻 Integration & Custom Module Development Guide (For Programmers)

Adding custom scan modules is straightforward. Follow this 4-step pipeline:

### Step 1: Add the CVE Metadata
Open [core/config.py](core/config.py) and declare your target vulnerability inside `CVE_DATABASE`:

```python
"CVE-202X-XXXX": {
    "id": "CVE-202X-XXXX",
    "short": "XXXXX",
    "title": "Your Custom Exploit Title",
    "type": "RCE / SSRF / Auth Bypass",
    "severity": "CRITICAL / HIGH / MEDIUM / LOW",
    "fix_version": "14.X.X",
    "description": "Short explanation of the vulnerability.",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-202X-XXXX"]
}
```

### Step 2: Register the Module
Open [modules/__init__.py](modules/__init__.py) and add your custom mapping:

```python
"XXXXX": {
    "name": "CVE-202X-XXXX",
    "title": "Module Short Title",
    "module": "modules.cve_xxxx",  # The python file inside the modules folder
    "function": "scan",            # The main entrypoint function
}
```

### Step 3: Implement the Scan Logic (`modules/cve_xxxx.py`)
Write your python file using this standard boilerplate to automatically integrate with the reporting ecosystem:

```python
#!/usr/bin/env python3
"""
NextSploit — CVE-202X-XXXX: Vulnerability Name
"""

import requests
from core.config import ScanConfig, CVE_DATABASE
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, print_finding

CVE_ID = "CVE-202X-XXXX"
CVE_INFO = CVE_DATABASE[CVE_ID]

def scan(config: ScanConfig) -> ModuleResult:
    # 1. Initialize the Module Result
    result = ModuleResult(
        cve=CVE_ID,
        title=CVE_INFO["title"],
        severity=CVE_INFO["severity"],
        status="NOT VULNERABLE"
    )
    
    # 2. Spawn customized session
    session = config.create_session()
    target = config.target.rstrip("/")
    
    log_info(f"Starting {CVE_ID} scan...")
    
    # [Pro-tip] Leverage global discovery variables if available:
    # build_id = config.discovered_build_id
    # action_ids = config.discovered_action_ids

    # 3. Scan & Exploit routines
    try:
        url = f"{target}/api/vulnerable-endpoint"
        r = session.get(url, timeout=config.timeout)
        
        # Match test logic
        if r.status_code == 200 and "exploit_indicator" in r.text:
            detail = f"Target exposed vulnerable behavior at {url}"
            log_warning(detail)
            
            # Store structured evidence
            evidence = {
                "endpoint": url,
                "payload": "default_request",
                "indicator": "exploit_indicator"
            }
            
            print_finding(CVE_ID, detail, evidence)
            
            # Save the finding
            result.add_finding(Finding(
                cve=CVE_ID,
                severity=CVE_INFO["severity"],
                title="Vulnerability Confirmed",
                status="VULNERABLE",
                detail=detail,
                evidence=evidence
            ))
            
    except requests.RequestException as e:
        result.error = str(e)
        
    return result
```

---

## 🛡️ Remediation & Mitigation Guide (For Users/Developers)

If NextSploit identifies a security exposure on your target web apps, refer to the remediation guide below:

### 1. SSRF via Header Injection (`CVE-2025-57822`)
*   **Root Cause**: Next.js server resolves dynamic or relative redirects by accepting absolute schemas inside headers (`Location`, `X-Forwarded-Host`) without strict protocol/domain verification.
*   **Mitigation**:
    *   Upgrade Next.js to **14.2.32 / 15.0.0** or newer.
    *   When performing custom redirects in your page code, always enforce relative routing patterns (`redirect('/dashboard')`) rather than accepting raw inputs.
    *   Implement strict whitelist matching if outbound redirections are absolutely required.

### 2. SSRF via Server Actions Host Header (`CVE-2024-34351`)
*   **Root Cause**: Server Actions construct absolute redirect destinations internally utilizing the HTTP `Host` header value sent in requests.
*   **Mitigation**:
    *   Upgrade Next.js to **14.1.1** or newer.
    *   Configure your Reverse Proxies or CDN layers (Nginx, Cloudflare) to sanitize and overwrite the `Host` header to the strict local upstream boundary host.

### 3. RCE via RSC Flight Protocol (`CVE-2025-66478` / React2Shell)
*   **Root Cause**: Unsafe parsing of incoming RSC Flight Protocol binary arrays in Server Actions allowing prototype pollution (`__proto__`) which can hijack module import resolvers.
*   **Mitigation**:
    *   Urgently patch Next.js to safe releases (**15.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7**).
    *   Disable Server Actions globally if they are not actively required by your app framework.

---

## ❓ Troubleshooting

### 1. SSL/HTTPS Validation Errors
*   **Symptoms**: NextSploit modules abort with `SSLError` or `certificate verify failed` messages.
*   **Solution**: NextSploit verifies HTTPS certificates by default. If auditing mock environments with self-signed certificates, edit the requests session initializer inside `core/config.py` to toggle `verify_ssl = False`.

### 2. High Density of False Positives on SSRF Probes
*   **Symptoms**: NextSploit tags every single request path as vulnerable.
*   **Solution**: NextSploit v2.0 enforces baseline comparison. If your server is configured with rigid redirect rules or custom error handlers, it may yield uniform response structures. If the returned sizes are identical, NextSploit v2.0 will safely suppress them. Ensure your baseline requests complete without network interference.

### 3. Network Connection Timeouts
*   **Symptoms**: Scan fails due to recurring `ConnectionTimeout` errors.
*   **Solution**: Boost the connection timeout in `core/config.py` by configuring `timeout: int = 20` or passing customized command parameters to avoid packet loss.

---

## 🙌 Credits & Attribution

This framework builds upon and integrates with the work of the following security researchers:

| Tool | Author | Contribution |
| :--- | :--- | :--- |
| **[NextSploit](https://github.com/AnonKryptiQuz/NextSploit)** | [AnonKryptiQuz](https://AnonKryptiQuz.github.io/) | Original CVE-2025-29927 scanner with Wappalyzer-based version detection & Selenium browser exploit engine (`open_bypassed_page`). The browser exploit chaining logic (`--browser` flag) is ported directly from this tool. |

---

## ⚠️ Disclaimer
**NextSploit is designed SOLELY for Educational Purposes and Authorized Penetration Testing campaigns.**

Running this tool against target domains without explicit, written authorization is strictly **illegal** and violates system administration regulations. Developers assume zero liability for damages, system downtime, or legal claims resulting from unauthorized utilization of this scanning framework.
