# 🔍 NextSploit: Next.js Multi-CVE Security Auditing Framework ⚠️

**NextSploit** is a modular, high-accuracy command-line penetration testing automation framework specifically designed to scan, detect, and analyze critical vulnerabilities in **Next.js** web applications. 

This framework builds upon the original concept of **[AnonKryptiQuz/NextSploit](https://github.com/AnonKryptiQuz/NextSploit)**. While the original focused specifically on CVE-2025-29927, **NextSploit v2.3.0** by **aarsaputra** (Original Author: **AnonKryptiQuz**) expands into a comprehensive Next.js auditing engine with 29 multi-vulnerability scanner modules (RCE, SSRF, Request Smuggling, DoS, Cache Poisoning, Authorization Bypass, and Source Exposure), thread-safe version signal aggregation, rate limiting, active/passive mode safety flags, and multi-branch version bounds (Next.js 13.x - 16.x).


---

## 🚀 **Features**

- **🔍 Automated Next.js Version & Build ID Detection**: Centralized `VersionState` aggregator crawls Next.js assets to fetch actual Build IDs, active Server Action IDs, and version signals across headers, build IDs, chunk bundles, and error leaks.
- **🛡️ Multi-CVE Vulnerability Assessment (29 Modules)**:
  - **Batch #1 (Mei 2026)**: CVE-2026-44573 (Pages i18n Bypass), CVE-2026-44578 (WebSocket SSRF), GHSA-mg66-mrh9-m8jx (PPR Deadlock DoS).
  - **Batch #2 (Juli 2026)**: CVE-2026-64641 (DoS SA CPU Exhaustion), CVE-2026-64642 (Middleware Bypass Turbopack+i18n), CVE-2026-64645 (SSRF Rewrites/Redirects), CVE-2026-64649 (SSRF SA Host Header), CVE-2026-64644 (DoS SVG Image API), CVE-2026-64646 (Edge SA Unbounded Payload), CVE-2026-64643 (SA Action ID Leak), CVE-2026-64648 (Fetch Cache Confusion), CVE-2026-64647 (Invalid UTF-8 Cache Confusion).
- **🔒 Active / Passive Mode Safety**: Potentially intrusive modules (OOB SSRF, shared cache differential tests) run in **passive mode by default**. Active execution requires explicit `--confirm-active` opt-in.
- **⚡ Rate Limiting & Delay**: Built-in `--rate-limit` (req/sec) and `--delay` (seconds between requests) to prevent target overloading and evade WAF throttling.
- **⚖️ FP Reduction & Confidence Scoring**: Precondition helpers (`has_app_router()`, `has_active_server_actions()`) skip non-applicable targets with `NOT_APPLICABLE` or `INCONCLUSIVE` statuses.
- **📊 JSON Report Schema v2.3**: `REPORT_SCHEMA_VERSION` 2.3 supports 5 status values (`VULNERABLE`, `NOT VULNERABLE`, `NOT_APPLICABLE`, `INCONCLUSIVE`, `ERROR`) for seamless CI/CD integration.
- **🌐 Automated Chrome Browser Chaining**: Integrates AnonKryptiQuz's Chrome Browser Exploit Engine to launch a Selenium-controlled Chrome window with preconfigured bypass headers.


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
   ```bash
   pip install -r requirements.txt
   ```
   *If `requirements.txt` is missing, install dependencies manually:*
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
| `--cve` | *None* | Executes specific scan modules by ID (comma-separated list) | `--cve 64645,64642,29927` |
| `--all` | *None* | Runs all registered scanning modules | `--all` |
| `--confirm-active` | *None* | **Opt-in flag** allowing modules to touch external hosts (OOB SSRF) or modify shared cache | `--all --confirm-active` |
| `--delay` | *None* | Delay in seconds between outbound HTTP requests (float/int) | `--delay 0.5` |
| `--rate-limit` | *None* | Maximum outbound requests per second (0 = unlimited) | `--rate-limit 5` |
| `-o` | `--output` | Saves the report (`.json`, `.html`, `.txt`) | `-o reports/scan.html` |
| `-v` | *None* | Verbose mode (displays rich analytical debugging logs) | `-v` |
| `-vv` | *None* | Extra Verbose mode (prints entire HTTP payloads and stack trace outputs) | `-vv` |
| `--browser` | *None* | **[AnonKryptiQuz integration]** Automatically opens Chrome with bypass headers via Selenium CDP | `--cve 29927 --browser` |
| `--list-modules`| *None* | Renders a table of all registered scanning modules | `--list-modules` |

### **Examples**

1. **Verify list of active modules:**
   ```bash
   python nextsploit.py --list-modules
   ```

2. **Perform deep scan on a target with active checks enabled & HTML output:**
   ```bash
   python nextsploit.py -t https://target.com --all --confirm-active --delay 0.2 -o reports/scan.html
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
│   ├── config.py            # Shared ScanConfig, HTTP session, CVE_DATABASE & save_response helper
│   ├── output.py            # Rich logging & console formatting functions
│   ├── reporter.py          # Domain extractor (get_domain) & Report exporter (JSON, HTML, TXT)
│   ├── version.py           # Application version constants (v2.3.0)
│   ├── version_state.py     # Centralized thread-safe version signal aggregator
│   ├── banner.py            # Custom ASCII Banner module
│   └── updater.py           # Dynamic release checker & update routine
├── modules/
│   ├── __init__.py          # Module registry and function mapping (29 Modules)
│   ├── fingerprint.py       # Tech stack identification & build asset crawler
│   ├── cve_29927.py         # Middleware Auth Bypass + Browser Exploit Chain
│   ├── cve_34351.py         # Server Action Host-Header SSRF validator
│   ├── cve_57822.py         # Baseline-safe SSRF Header Scanner
│   ├── cve_55183.py         # Source Code Exposure Scanner
│   ├── cve_55184.py         # DoS Detection (Passive) Scanner
│   ├── cve_66478.py         # React2Shell RSC Deserialization scanner (Passive)
│   ├── cve_46982.py         # Cache Poisoning / Stored XSS Scanner
│   ├── cve_56332.py         # Pathname Middleware Bypass Scanner
│   ├── cve_48068.py         # Dev Server Source Exposure Scanner
│   ├── cve_34350.py         # HTTP Request Smuggling Check Scanner
│   ├── cve_59471.py         # Image Optimizer DoS Check Scanner
│   ├── cve_23870.py         # DoS via RSC Deserialization Scanner
│   ├── cve_67779.py         # DoS Incomplete Fix — Infinite Promise Loop Scanner
│   ├── cve_44575.py         # Middleware Bypass via Segment-Prefetch (.rsc)
│   ├── cve_23864.py         # RSC Memory Exhaustion DoS via FormData $K tokens
│   ├── ghsa_mg66.py         # PPR/Cache Components Deadlock DoS
│   ├── cve_45109.py         # Middleware Bypass via Turbopack (incomplete fix)
│   ├── cve_64645.py         # SSRF via rewrites()/redirects() Hostname Injection
│   ├── cve_64642.py         # Middleware Bypass via App Router + Turbopack + Single Locale
│   ├── cve_64641.py         # DoS App Router via Server Actions CPU Exhaustion
│   ├── cve_64649.py         # SSRF Server Actions via Host Header (Custom Server)
│   ├── cve_44573.py         # Pages Router i18n Data-Route Middleware Bypass
│   ├── cve_44578.py         # WebSocket Upgrade SSRF (Self-Hosted, 16.x only)
│   ├── cve_64643.py         # Server Action / use cache Endpoint ID Leak
│   ├── cve_64644.py         # DoS Image Optimization API via SVG
│   ├── cve_64646.py         # Unbounded SA Payload Edge Runtime Memory Exhaustion
│   ├── cve_64648.py         # Cache Confusion via fetch() Response Body Mismatch
│   ├── cve_64647.py         # Cache Confusion via Invalid UTF-8 Request Body
│   └── rsc_attack.py        # RSC Protocol & Server Actions Audit
└── reports/
    └── <domain>/            # Target-isolated report storage (JSON reports & HTTP response artifacts)
```

---

## 🧪 **Available Scanning Modules (29 Modules)**

| Module CLI Key (`--cve`) | CVE / ID | Vulnerability Type | Severity | Fix Version (15.x / 16.x) | Execution Mode |
|:---:|:---|:---|:---:|:---:|:---:|
| `64645` | CVE-2026-64645 | SSRF via rewrites()/redirects() Hostname Injection | HIGH | 15.5.21 / 16.2.11 | ⚡ needs `--confirm-active` |
| `64642` | CVE-2026-64642 | Middleware Bypass — Turbopack + Single Locale | HIGH | 16.2.11 (16.x only) | 🔒 passive default |
| `64641` | CVE-2026-64641 | DoS App Router via Server Actions CPU Exhaustion | HIGH | 15.5.21 / 16.2.11 | 🔒 passive default |
| `64649` | CVE-2026-64649 | SSRF Server Actions Host Header (Custom Server) | HIGH | 15.5.21 / 16.2.11 | ⚡ needs `--confirm-active` |
| `44573` | CVE-2026-44573 | Pages Router i18n Data-Route Middleware Bypass | HIGH | 15.5.16 / 16.2.5 | 🔒 passive default |
| `44578` | CVE-2026-44578 | WebSocket Upgrade SSRF (Self-Hosted, 16.x only) | HIGH | 16.2.5 (16.x only) | 🔒 passive default |
| `64643` | CVE-2026-64643 | Server Action / use cache Endpoint ID Leak | MEDIUM | 15.5.21 / 16.2.11 | 🔒 passive default |
| `64644` | CVE-2026-64644 | DoS Image Optimization API via SVG | MEDIUM | 15.5.21 / 16.2.11 | 🔒 passive default |
| `64646` | CVE-2026-64646 | Unbounded SA Payload Edge Runtime Memory Exh. | MEDIUM | 15.5.21 / 16.2.11 | 🔒 passive default |
| `64648` | CVE-2026-64648 | Cache Confusion — fetch() Response Body Mismatch | MEDIUM | 15.5.21 / 16.2.11 | ⚡ needs `--confirm-active` |
| `64647` | CVE-2026-64647 | Cache Confusion — Invalid UTF-8 Request Body | MEDIUM | 15.5.21 / 16.2.11 | ⚡ needs `--confirm-active` |
| `29927` | CVE-2025-29927 | Middleware Auth Bypass | CRITICAL | 14.2.25 | 🔒 passive default |
| `66478` | CVE-2025-66478 | React2Shell RCE via RSC Flight | CRITICAL | 15.0.5 | 🔒 passive default |
| `57822` | CVE-2025-57822 | SSRF via HTTP Headers | HIGH | 14.2.32 | 🔒 passive default |
| `34351` | CVE-2024-34351 | SSRF via Server Action Host | HIGH | 14.1.1 | 🔒 passive default |
| `55183` | CVE-2025-55183 | Source Code Exposure | MEDIUM | 14.2.35 | 🔒 passive default |
| `55184` | CVE-2025-55184 | DoS Detection (Passive) | HIGH | 14.2.35 | 🔒 passive default |
| `46982` | CVE-2024-46982 | Cache Poisoning / Stored XSS | HIGH | 14.2.10 | 🔒 passive default |
| `56332` | CVE-2024-56332 | Pathname Middleware Bypass | HIGH | 14.2.25 | 🔒 passive default |
| `48068` | CVE-2025-48068 | Dev Server Source Exposure | MEDIUM | 15.2.2 | 🔒 passive default |
| `34350` | CVE-2024-34350 | HTTP Request Smuggling | HIGH | 13.5.1 | 🔒 passive default |
| `59471` | CVE-2025-59471 | Image Optimizer DoS Check | MEDIUM | 15.5.10 | 🔒 passive default |
| `23870` | CVE-2026-23870 | DoS via RSC Deserialization | HIGH | 15.5.16 | 🔒 passive default |
| `67779` | CVE-2025-67779 | DoS via Infinite Promise Loop | HIGH | 15.5.9 | 🔒 passive default |
| `44575` | CVE-2026-44575 | Middleware Bypass (.rsc / prefetch) | HIGH | 15.5.16 | 🔒 passive default |
| `23864` | CVE-2026-23864 | DoS RSC Memory Exhaustion ($K) | HIGH | 15.5.10 | 🔒 passive default |
| `mg66`  | GHSA-mg66-mrh9-m8jx | DoS PPR/Cache Components Deadlock | HIGH | 15.5.16 / 16.2.5 | 🔒 passive default |
| `45109` | CVE-2026-45109 | Middleware Bypass via Turbopack | HIGH | 15.5.18 | 🔒 passive default |
| `rsc`   | RSC-Attack | RSC Protocol & Server Actions Audit | INFO | All App Router versions | 🔒 passive default |

---

## 🧪 **CVE Coverage Matrix (Verified GHSA Boundaries)**

| Release | CVE / ID | Severity | Affected Ranges | Fixed In |
|:---|:---|:---:|:---|:---:|
| **July 2026** | CVE-2026-64645 | HIGH | `>= 12.0.0, < 15.5.21` \| `>= 16.0.0, < 16.2.11` | 15.5.21 / 16.2.11 |
| **July 2026** | CVE-2026-64642 | HIGH | `>= 16.0.0, < 16.2.11` (16.x only) | 16.2.11 |
| **July 2026** | CVE-2026-64641 | HIGH | `>= 13.0.0, < 15.5.21` \| `>= 16.0.0, < 16.2.11` | 15.5.21 / 16.2.11 |
| **July 2026** | CVE-2026-64649 | HIGH | `>= 14.1.1, < 15.5.21` \| `>= 16.0.0, < 16.2.11` | 15.5.21 / 16.2.11 |
| **July 2026** | CVE-2026-64644 | MEDIUM | `>= 15.5.0, < 15.5.21` \| `>= 16.0.0, < 16.2.11` | 15.5.21 / 16.2.11 |
| **July 2026** | CVE-2026-64646 | MEDIUM | `>= 13.0.0, < 15.5.21` \| `>= 16.0.0, < 16.2.11` | 15.5.21 / 16.2.11 |
| **July 2026** | CVE-2026-64643 | MEDIUM | `>= 13.0.0, < 15.5.21` \| `>= 16.0.0, < 16.2.11` | 15.5.21 / 16.2.11 |
| **July 2026** | CVE-2026-64648 | MEDIUM | `>= 13.0.0, < 15.5.21` \| `>= 16.0.0, < 16.2.11` | 15.5.21 / 16.2.11 |
| **July 2026** | CVE-2026-64647 | MEDIUM | `>= 13.0.0, < 15.5.21` \| `>= 16.0.0, < 16.2.11` (App Router) | 15.5.21 / 16.2.11 |
| **May 2026** | CVE-2026-44573 | HIGH | `>= 12.2.0, < 15.5.16` \| `>= 16.0.0, < 16.2.5` | 15.5.16 / 16.2.5 |
| **May 2026** | CVE-2026-44578 | HIGH | `>= 16.0.0, < 16.2.5` (16.x only) | 16.2.5 |
| **May 2026** | CVE-2026-44579 (mg66) | HIGH | `>= 15.0.0, < 15.5.16` \| `>= 16.0.0, < 16.2.5` | 15.5.16 / 16.2.5 |

---

## 📖 **Status Legend**

| Status | Meaning |
|:---|:---|
| `VULNERABLE` | Vulnerability indicator confirmed above confidence threshold. |
| `NOT VULNERABLE` (SAFE) | Full scan completed; no vulnerability indicators detected. |
| `NOT_APPLICABLE` | Target does not fulfill preconditions (e.g., missing App Router or active Server Actions) — module skipped. |
| `INCONCLUSIVE` | Black-box precondition could not be fully verified or WAF rate-limiting interfered — manual review recommended. |
| `ERROR` | Execution failed due to a network, connection, or parsing error. |

---

## ⚠️ **Disclaimer**

- **Educational Purposes Only**: This tool is intended solely for security research, ethical hacking, and authorized penetration testing campaigns. The user is entirely responsible for ensuring compliance with local laws and regulations.
- **No Liability**: The authors assume zero liability and are not responsible for any damage, server downtime, or legal claims resulting from the utilization of this framework.
- **Manual Verification Recommended**: Results generated by automated signatures should be manually verified (using the `--browser` flag or Burp Suite) before drawing final conclusions.

---

## 🐐 **Authors & Credits**

- **Original Creator**: **[AnonKryptiQuz](https://AnonKryptiQuz.github.io/)** — Author of the original NextSploit scanner and the pioneer of the browser-based Selenium CDP middleware bypass verification.
- **Refactoring & Expansion**: **aarsaputra** — Extended into v2.3.0 with 29 multi-CVE modules, centralized version state aggregator, multi-branch version bounds, active/passive safety controls, rate-limiting, and reporting engine.
