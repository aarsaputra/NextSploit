# 🔍 NextSploit: Next.js Security Auditing & Vulnerability Discovery Framework ⚠️

**NextSploit v4.0.0-alpha** is an enterprise-grade, modular, high-accuracy security auditing and vulnerability discovery framework specifically architected for **Next.js** web applications. 

NextSploit v4 features an autonomous **Multi-Phase Scan Pipeline**, a **Multi-Signal Version Detection Engine**, policy-based risk management (`safe`, `bugbounty`, `pentest`, `ci`), dynamic YAML Rule Engine execution, Replay Verification, and a Plugin Diagnostic Sandbox.

---

## 🚀 **Key Features**

- **🔍 Multi-Signal Version & Tech Stack Fingerprinting**: 
  - Centralized semver resolution using priority chunk mining (`framework`, `webpack`, `main`, `turbopack`), `window.next` version parsing, `package.json` inline metadata extraction, exposed sourcemap correlation, error payload leakage, and React-to-Next.js version range matrix.
  - Automatically identifies Router Architecture (**App Router** / **Pages Router**), Build IDs, Server Actions, Turbopack, and RSC (React Server Components) capabilities.
- **🛡️ Phase-Driven Execution Pipeline**:
  - **Phase 1: Target Validation** — DNS resolution & HTTP connectivity checks.
  - **Phase 2: Recon & WAF Detection** — Identifies Cloudflare, Netlify, Vercel, `robots.txt`, and `sitemap.xml`.
  - **Phase 3: Fingerprinting** — Framework version, router architecture, and JS chunk harvesting.
  - **Phase 4: Plugin Execution** — Dynamic execution of modern and legacy modular vulnerability verification plugins.
  - **Phase 5: Rule-Based Detection** — High-performance YAML Detection Rule Engine matching target profiles.
- **⚖️ Policy-Based Risk Management**:
  - **`safe`** *(Default)*: Non-intrusive scanning profile. Active testing plugins and dangerous rules are automatically disabled.
  - **`bugbounty`**: Active testing enabled with controlled concurrency, rate limiting, and extended timeouts.
  - **`pentest`**: Full active testing profile for authorized internal penetration testing campaigns.
  - **`ci`**: Lightweight non-blocking profile optimized for CI/CD pipelines.
- **🔄 Replay Engine**:
  - Re-verify past findings from JSON report manifests using `SMART`, `STRICT`, or `DIFF` analysis modes.
- **🔌 Plugin Doctor & Diagnostics**:
  - Built-in sandbox diagnostics to verify plugin manifests, runtime stability, and health scores (`nextsploit plugin doctor`).
- **📚 Rule Documentation Generator & Schema Validator**:
  - Auto-generate clean Markdown documentation from YAML detection rules and validate rule schema compliance (`nextsploit docs`).
- **📊 Multi-Format Reporting Engine**:
  - Exports interactive enterprise HTML dashboards, structured JSON manifests, GitHub SARIF format, or Markdown summaries.

---

## 🛠️ **Requirements**

- **🐍 Python 3.8+**
- **Dependencies**: `requests`, `rich`, `urllib3`, `colorama`

---

## 📥 **Installation**

1. **Clone the repository:**
   ```bash
   git clone git@github.com:aarsaputra/NextSploit.git
   cd NextSploit
   ```

2. **Install required packages:**
   ```bash
   pip install -r requirements.txt
   ```
   *Or install core dependencies manually:*
   ```bash
   pip install requests rich urllib3 colorama
   ```

---

## 💻 **Usage & Commands**

NextSploit v4 features a clean subcommand-routed CLI structure:

```bash
python nextsploit.py [SUBCOMMAND] [OPTIONS]
```

### 1. **Vulnerability Scanning (`scan`)**

Run a target scan pipeline (Validation → Recon → Fingerprinting → Active Testing → Rule Detection):

```bash
# Standard Scan (Safe Policy by default)
python nextsploit.py -t https://target.com

# Bug Bounty Profile with Custom User-Agent & HTML Export
python nextsploit.py scan -t https://target.com --policy bugbounty --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -o reports/encoteki_report.html

# Scan via HTTP Proxy (Burp Suite) with Verbose Output
python nextsploit.py -t https://target.com --proxy http://127.0.0.1:8080 --no-verify -v

# Batch Scan from Target List File
python nextsploit.py -T targets.txt --policy bugbounty --threads 10 -o batch_report.json
```

#### **Scan Options & Parameters**

| Flag | Long Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `-t` | `--target` | Target URL (e.g., `https://target.com`) | *None* |
| `-T` | `--target-file` | Path to a text file containing target URLs | *None* |
| `--policy` | *None* | Policy profile (`safe`, `bugbounty`, `pentest`, `ci`) | `safe` |
| `--user-agent` | *None* | Custom HTTP User-Agent header string | *NextSploit/4.0.0* |
| `--proxy` | *None* | Proxy URL (`http://127.0.0.1:8080`) | *None* |
| `--no-verify` | *None* | Disable SSL certificate verification | `False` |
| `--timeout` | *None* | HTTP request timeout in seconds | `10` |
| `--threads` | *None* | Concurrency worker threads | `10` |
| `-o` | `--output` | Save report (`.html`, `.json`, `.sarif`, `.md`) | *None* |
| `-v` / `-vv` | `--verbose` | Increase verbosity level for detailed debugging logs | `0` |
| `-q` | `--quiet` | Suppress non-essential console output | `False` |

---

### 2. **Replaying & Re-verifying Findings (`replay`)**

Replay findings directly from a previously generated JSON scan report manifest to verify fix status:

```bash
# Replay all findings using SMART analysis mode
python nextsploit.py replay reports/scan_report.json --mode SMART

# Replay only HIGH severity findings
python nextsploit.py replay reports/scan_report.json --only high

# Replay findings for a specific module ID
python nextsploit.py replay reports/scan_report.json --module cve-2025-29927
```

---

### 3. **Plugin Management & Diagnostics (`plugin`)**

Manage installed plugins and run health checks:

```bash
# List all loaded plugins and their policy permissions
python nextsploit.py plugin list

# Show detailed information for a specific plugin ID
python nextsploit.py plugin info next.sample.modern

# Run thorough health diagnostics on a plugin directory
python nextsploit.py plugin doctor plugins/sample_modern/

# Enable or disable a plugin
python nextsploit.py plugin enable next.sample.modern
python nextsploit.py plugin disable next.sample.legacy
```

---

### 4. **Rule Engine & Documentation Generator (`docs`)**

Validate YAML detection rules or generate Markdown documentation:

```bash
# Validate all YAML detection rule schemas and ID uniqueness
python nextsploit.py docs validate --rules-dir knowledge/rules/core

# Generate Markdown documentation from YAML detection rules
python nextsploit.py docs generate --rules-dir knowledge/rules/core --output-dir docs/detections
```

---

## 📂 **Project Architecture**

```text
NextSploit/
├── nextsploit.py                    # Main CLI Entrypoint forwarding to nextsploit/cli.py
├── nextsploit/
│   ├── cli.py                       # CLI parsing, subcommand routing, and scan handlers
│   ├── core/                        # Core context, config, container, logger, and KB loaders
│   ├── interfaces/                  # Abstract interfaces (Plugin, Rule, Policy, Reporter)
│   ├── phases/                      # Scan pipeline phases (Validation, Recon, Fingerprint, Active, Rules)
│   ├── pipeline/                    # Pipeline executor & phase registry
│   ├── policies/                    # Policy JSON profiles (safe.json, bugbounty.json, pentest.json, ci.json)
│   └── services/                    # Core engines (PolicyEngine, RiskEngine, ReplayEngine, DocGenerator)
├── core/
│   └── version_detect.py            # Multi-Signal Version Detection Engine
├── knowledge/
│   ├── rules/core/                  # YAML Detection Rules (CVE-2025-29927, Middleware checks, etc.)
│   └── fingerprints/                # Tech stack fingerprinting definitions
├── docs/                            # Generated & framework documentation
└── reports/                         # Default export directory for scan reports
```

---

## ⚠️ **Disclaimer**

- **Educational & Ethical Use Only**: This framework is intended solely for security research, authorized penetration testing, and bug bounty hunting on targets you own or have explicit permission to test.
- **No Liability**: The authors assume zero liability for misuse, unauthorized scanning, or target server downtime caused by this tool.

---

## 🐐 **Authors & Credits**

- **Author & Lead Developer**: **aarsaputra**
- **Original Concept & Middleware Bypass Research**: **AnonKryptiQuz**
