# NextSploit Development Roadmap v2 — Post-Freeze Ecosystem Strategy

Following the successful architecture freeze (Sprint 0–6B) with 60/60 test coverage and complete framework core maturity, NextSploit pivots from core engine development to **Detection Capability, Intelligence, and Ecosystem Engineering**.

---

## 🗺️ Strategic Phase Overview

```
Framework Engine (Frozen)  ──>  Detection Intelligence (Active)  ──>  Public Ecosystem
───────────────────────────────  ───────────────────────────────  ────────────────
Sprint 0 : Foundation           Phase A : Detection Packs         Phase E : Public Packaging
Sprint 1 : Pipeline             Phase B : Knowledge Base Packs    Phase F : Community Guidelines
Sprint 2 : Recon & Profile      Phase C : Next.js Test Lab
Sprint 3 : Plugin SDK & Policy  Phase D : Quality & Metrology
Sprint 4 : Event/Risk/Metrics
Sprint 5 : Replay & Reporter
Sprint 6 : YAML Rule Engine
```

---

## Phase Breakdown

### Phase A — Detection Packs (High Priority)
Expand YAML rules and passive/active plugins across key Next.js subsystems:
- `knowledge/rules/core/packs/nextjs/middleware/`
- `knowledge/rules/core/packs/nextjs/server_actions/`
- `knowledge/rules/core/packs/nextjs/rsc/`
- `knowledge/rules/core/packs/nextjs/image/`
- `knowledge/rules/core/packs/nextjs/cache/`
- `knowledge/rules/core/packs/nextjs/turbopack/`
- `knowledge/rules/core/packs/nextjs/build_artifacts/`

### Phase B — Knowledge Base Expansion
Structured vulnerability metadata per CVE:
- `knowledge/cves/CVE-2025-29927/` (`metadata.json`, `remediation.md`, `references.yaml`)
- Centralized payload registries for SSRF, Header Injection, and Deserialization probes.

### Phase C — Next.js Regression Test Lab
Dockerized multi-version test environment (`labs/`):
- Next.js 13, 14, 15, 16 test targets.
- Profiles: `patched`, `vulnerable`, `misconfigured`.

### Phase D — Detection Quality & Metrics
Metrics dashboard tracking:
- Accuracy %
- False Positive (FP) count
- False Negative (FN) count
- Confidence scoring verification.

### Phase E — Public Release & Packaging
- PyPI distribution (`pip install nextsploit`).
- Official Docker container (`docker pull nextsploit/nextsploit`).
- Clean CLI commands (`nextsploit scan`, `nextsploit replay`, `nextsploit docs`).

### Phase F — Community & Governance
Open-source contribution guidelines:
- `CONTRIBUTING.md`
- `SECURITY.md`
- `CODE_OF_CONDUCT.md`
- `RULE_AUTHOR_GUIDE.md`
- Issue and Rule PR templates.
