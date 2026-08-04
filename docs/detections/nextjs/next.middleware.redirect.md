# next.middleware.redirect — Next.js Middleware Open Redirect

## Metadata

- **Rule ID**: `next.middleware.redirect`
- **Severity**: `HIGH`
- **Confidence**: `0.8`
- **CVE**: `N/A`
- **CWE**: `CWE-601`
- **OWASP Top 10**: `A03:2021`
- **Author**: `NextSploit Team`
- **Tags**: `nextjs, middleware, open-redirect, high`

## Execution Profile

- **Rule Type**: Declarative YAML
- **Execution Phase**: `RuleExecutionPhase` (Phase 5)
- **Detection Method**: Black-box Probing
- **Target Technology**: `nextjs`
- **Target Version Constraint**: `*`
- **Required Capabilities**: `middleware`

## Probed Endpoints & Headers

### Probed Paths
- `/auth/callback?return_to=https://evil.example.com/phishing`
- `/login?redirect=https://evil.example.com/phishing`
- `/redirect?next=https://evil.example.com/phishing`
- `/?next=https://evil.example.com/phishing`

### Request Headers
  - `accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`
  - `user-agent: Mozilla/5.0 (NextSploit Security Auditor)`


## Match Logic

- **Conditions**: All match conditions must evaluate to `TRUE`
- **status**: `equals` = `302`
- **regex**: `regex` = `https?://evil\.example\.com`

## Remediation

Validate and allowlist redirect URLs in middleware. Do not blindly redirect to
any user-supplied URL. Implement the following defenses:
1. Check that the redirect target matches an allowlist of trusted domains.
2. Use relative URLs for internal redirects instead of absolute URLs.
3. Reject or sanitize any redirect parameter that starts with 'http://' or 'https://'.
4. Log and alert on redirect attempts to non-allowlisted external domains.


## References

- <https://cwe.mitre.org/data/definitions/601.html>
