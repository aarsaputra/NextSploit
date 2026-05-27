# 🔍 NextSploit: Next.js CVE-2025-29927 & Multi-CVE Security Auditing Framework ⚠️

**NextSploit** is a modular, high-accuracy command-line penetration testing automation framework specifically designed to scan, detect, and analyze critical vulnerabilities in **Next.js** web applications. 

This framework builds upon the original concept of **[AnonKryptiQuz/NextSploit](https://github.com/AnonKryptiQuz/NextSploit)**. While the original focused specifically on CVE-2025-29927, **NextSploit v2.2.0** by **aarsaputra** (Original Author: **AnonKryptiQuz**) expands into a comprehensive Next.js auditing engine with multi-vulnerability capabilities (RCE, SSRF, Request Smuggling, DoS, Cache Poisoning, and Source Exposure), baseline validation, and an automated GitHub release checker engine.


---

## 🚀 **Features**

- **🔍 Automated Next.js Version & Build ID Detection**: Passively and active fingerprinters crawl Next.js assets to fetch actual Build IDs and active Server Action IDs.
- **🛡️ Multi-CVE Vulnerability Assessment**:
  - **CVE-2025-29927 (Middleware Auth Bypass)**: Detects and visualizes middleware authentication bypasses.
  - **CVE-2025-66478 (React2Shell RCE)**: Assesses server-side React Server Components (RSC) Flight Protocol deserialization bugs.
  - **CVE-2024-34351 (Server Action SSRF)**: Validates outbound redirections via Host Header manipulation.
  - **CVE-2024-46982 (Cache Poisoning / Stored XSS)**: Tests for fallback Route Matches cache injections.
  - **CVE-2024-56332 (Pathname Middleware Bypass)**: Evaluates auth controls against traversal and URL-encoded variants.
  - **CVE-2025-48068 (Dev Server Source Exposure)**: Identifies development bundle exposures using spoofed origins.
  - **CVE-2024-34350 (HTTP Request Smuggling)**: Analyzes targets for HTTP Smuggling and Response Queue Poisoning.
  - **CVE-2025-59471 (Image Optimizer DoS)**: Checks for unauthenticated dynamic OOM Denial of Service API flags.
  - **CVE-2026-23870 (RSC Deserialization DoS)**: Assesses Server Function routes against DoS deserialization exploits.
- **⚖️ FP Reduction & Confidence Scoring**: Introduces baseline hashing, filtering out static script differences, and rates findings on a `0.0` - `1.0` confidence scale.
- **🌐 Automated Chrome Browser Chaining**: Integrates AnonKryptiQuz's Chrome Browser Exploit Engine to automatically launch a Selenium-controlled Chrome window with preconfigured bypass headers.
- **📡 Multiformat Reporting & Self-Update**: Renders findings immediately, supports dynamic update checking using GitHub API, and self-updates using `--update`.


---

## **Requirements** 🛠️

To run NextSploit and use its browser exploit chaining features, you need:
- **🐍 Python 3.8+**
- **🧪 Selenium** (Python Package)
- **🚗 ChromeDriver** & **🦊 GeckoDriver** (system path accessible)
- **🌐 Google Chrome** (for browser-based live validation)
- **rich** & **requests** (for styling and HTTP parsing)

---

## **Installation** 📥

1. **Clone the repository:**
   ```bash
   git clone git@github.com:aarsaputra/NextSploit.git
   cd NextSploit
   ```

2. **Install required packages:**
   NextSploit features a virtual environment fallback. You can set it up inside your preferred virtual environment:
   ```bash
   pip install -r requirements.txt
   ```
   *If `requirements.txt` is missing, install the dependencies manually:*
   ```bash
   pip install requests rich urllib3 selenium prompt_toolkit colorama
   ```

3. **Driver Configuration:**
   Make sure `chromedriver` is installed on your Kali Linux or Debian system:
   ```bash
   sudo apt update
   sudo apt install chromium-driver -y
   ```

---

## **Usage** 💻

NextSploit provides a highly flexible Command-Line Interface (CLI):

```bash
python nextsploit.py -t <TARGET_URL> [options]
```

### **Complete CLI Parameters**

| Parameter | Alternative | Description | Example Usage |
| :--- | :--- | :--- | :--- |
| `-t` | `--target` | Target URL of the Next.js app (Required, except for `--list-modules`) | `-t https://target.com` |
| `--fingerprint` | *None* | Runs fingerprinting probes only (version, Build ID, Action IDs) | `--fingerprint` |
| `--cve` | *None* | Executes specific scan modules by ID (comma-separated list) | `--cve 29927,46982` |
| `--all` | *None* | Runs all registered scanning modules | `--all` |
| `-o` | `--output` | Saves the report (automatically infers format: `.json`, `.html`, `.txt`) | `-o reports/scan.html` |
| `-v` | *None* | Verbose mode (displays rich analytical debugging logs) | `-v` |
| `-vv` | *None* | Extra Verbose mode (prints entire HTTP payloads and stack trace outputs) | `-vv` |
| `--browser` | *None* | **[AnonKryptiQuz integration]** Automatically opens Chrome with bypass headers injected via Selenium CDP for live visual validation. | `--cve 29927 --browser` |
| `--list-modules`| *None* | Renders a table of all registered scanning modules | `--list-modules` |

### **Examples**

1. **Verify list of active modules:**
   ```bash
   python nextsploit.py --list-modules
   ```

2. **Perform deep scan on a target with HTML output:**
   ```bash
   python nextsploit.py -t https://target.com --all -o reports/scan.html
   ```

3. **Chain CVE-2025-29927 scan into Chrome browser visual exploitation:**
   ```bash
   python nextsploit.py -t https://target.com --cve 29927 --browser
   ```

---

## 📂 **Project Architecture**

```text
NextSploit/
├── nextsploit.py            # CLI Entrypoint & scan orchestrator
├── core/
│   ├── config.py            # Shared CVE database & customized requests session
│   ├── output.py            # Rich logging formatting functions
│   ├── reporter.py          # Multiformat report exporter (JSON, HTML, TXT)
│   ├── version.py           # Application version constants
│   ├── banner.py            # Custom ASCII Banner module
│   └── updater.py           # Dynamic release checker & update routine
└── modules/
    ├── __init__.py          # Module registry and function mapping
    ├── fingerprint.py       # Tech stack identification & build asset crawler
    ├── cve_29927.py         # Middleware Auth Bypass + Browser Exploit Chain (AnonKryptiQuz)
    ├── cve_34351.py         # Server Action Host-Header SSRF validator
    ├── cve_57822.py         # Baseline-safe SSRF Header Scanner
    ├── cve_66478.py         # React2Shell RSC Deserialization scanner (Passive)
    ├── cve_46982.py         # Cache Poisoning / Stored XSS Scanner
    ├── cve_56332.py         # Pathname Middleware Bypass Scanner
    ├── cve_48068.py         # Dev Server Source Exposure Scanner
    ├── cve_34350.py         # HTTP Request Smuggling Check Scanner
    ├── cve_59471.py         # Image Optimizer DoS Check Scanner
    └── cve_23870.py         # DoS via RSC Deserialization Scanner

```

### **How the Orchestrator Works:**
1. **Target Normalization**: NextSploit formats the target URL and configures the HTTP session.
2. **Mandatory Fingerprinting**: It crawls common static assets (e.g. `/_next/static/chunks/`) to fetch Build IDs and checks headers for specific server identifiers.
3. **Context Object Propagation**: Discovered Build IDs and Action IDs are bound inside a `ScanConfig` instance, letting all active modules access them instantly.
4. **Scan Execution**: For each selected module, NextSploit dynamically imports the module file and calls the `scan(config)` handler.
5. **Confidence Rating**: Findings are created with custom scores (0.0 to 1.0) and written to the selected output report.

---

## 💻 **Programmer's Extension & Customization Guide**

NextSploit is designed to easily accommodate new CVE modules. Follow these steps to contribute a new vulnerability scan module:

### **1. Update the Database**
Add your target CVE metadata to the `CVE_DATABASE` dictionary in [core/config.py](core/config.py):
```python
"CVE-202X-XXXX": {
    "id": "CVE-202X-XXXX",
    "short": "XXXXX",
    "title": "Vulnerability title",
    "type": "RCE / SSRF / Auth Bypass / Info Disclosure",
    "severity": "CRITICAL / HIGH / MEDIUM / LOW",
    "fix_version": "15.x.x",
    "description": "Provide a descriptive summary of the flaw.",
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-202X-XXXX"]
}
```

### **2. Register in Registry**
Open [modules/__init__.py](modules/__init__.py) and add a key mapping:
```python
"XXXXX": {
    "name": "CVE-202X-XXXX",
    "title": "Short Title",
    "module": "modules.cve_xxxx", # Matches your module filename
    "function": "scan",           # Module main function
}
```

### **3. Implement the Exploit Logic (`modules/cve_xxxx.py`)**
Use this template to build your scan module:
```python
#!/usr/bin/env python3
"""
NextSploit — CVE-202X-XXXX: Module Implementation
"""

import requests
from core.config import ScanConfig, CVE_DATABASE
from core.reporter import ModuleResult, Finding
from core.output import log_info, log_success, log_warning, print_finding

CVE_ID = "CVE-202X-XXXX"
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
    
    # You can access properties discovered globally:
    # build_id = config.discovered_build_id
    
    try:
        url = f"{target}/specific-vulnerable-endpoint"
        r = session.get(url, timeout=config.timeout)
        
        if r.status_code == 200 and "exploit_indicator" in r.text:
            detail = f"Target exposed vulnerability at {url}"
            log_warning(detail)
            
            evidence = {
                "url": url,
                "response_indicator": "exploit_indicator"
            }
            
            print_finding(CVE_ID, detail, evidence)
            
            result.add_finding(Finding(
                cve=CVE_ID,
                severity=CVE_INFO["severity"],
                title="Vulnerability Confirmed",
                status="VULNERABLE",
                detail=detail,
                evidence=evidence,
                confidence=0.9 # Set a baseline confidence score (0.0 - 1.0)
            ))
            
    except requests.RequestException as e:
        result.error = str(e)
        
    return result
```

---

## ⚠️ **Disclaimer**

- **Educational Purposes Only**: This tool is intended solely for security research, ethical hacking, and authorized penetration testing campaigns. The user is entirely responsible for ensuring compliance with local laws and regulations.
- **No Liability**: The authors assume zero liability and are not responsible for any damage, server downtime, or legal claims resulting from the utilization of this framework.
- **Manual Verification Recommended**: Results generated by automated signatures should be manually verified (using the `--browser` flag or Burp Suite) before drawing final conclusions.

---

## 🐐 **Authors & Credits**

- **Original Creator**: **[AnonKryptiQuz](https://AnonKryptiQuz.github.io/)** — Author of the original NextSploit scanner and the pioneer of the browser-based Selenium CDP middleware bypass verification.
- **Refactoring & Expansion**: **aarsaputra** — Extended into v2.2.0 with multi-CVE scanning, baseline verification, update notification mechanism, dynamic Rich banners, and a professional reporting engine.

