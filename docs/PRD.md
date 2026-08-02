# NextSploit v4 - Product Requirements Document (PRD)

## 1. Vision & Purpose
NextSploit is a modular, enterprise-grade security auditing framework dedicated exclusively to the Next.js ecosystem. It focuses on identifying vulnerabilities, framework disclosures, and routing misconfigurations.

## 2. Core Security Guidelines
- **Safety First**: Non-destructive scanning only. No remote execution payloads that modify target state or files.
- **Evidence-Driven**: Every finding must gather HTTP Request/Response templates, timing, and confidence scores.
- **Opt-In Active Validation**: Active checks are gated under the `--confirm-active` flag and regulated by execution policies.

## 3. Scope Rules
- Target framework: Next.js (App Router, Pages Router, and associated dependencies).
- Generic attacks (WordPress, Drupal, generic SQLi/XSS) are out of scope.
