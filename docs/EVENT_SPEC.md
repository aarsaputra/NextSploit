# NextSploit v4 - Event Specification

This document lists all system events published on the central `EventBus` and their expected payload schemas.

## 1. System Events

### `TARGET_VALIDATED`
- **Description**: Triggered after the target URL is verified, DNS is resolved, and connectivity is established.
- **Payload**:
  ```json
  {
    "url": "https://target.com",
    "ip": "1.2.3.4",
    "dns_resolved": true
  }
  ```

### `RECON_COMPLETE`
- **Description**: Triggered when sitemap, headers, robots, and cookies scanning completes.
- **Payload**:
  ```json
  {
    "headers": { ... },
    "cookies": [ ... ]
  }
  ```

### `FEATURE_DISCOVERED`
- **Description**: Triggered when a target feature/capability is discovered (e.g. Server Actions).
- **Payload**:
  ```json
  {
    "name": "server_actions",
    "detected": true,
    "confidence": 0.95
  }
  ```

### `FINDING_FOUND`
- **Description**: Triggered when a vulnerability finding is recorded.
- **Payload**:
  ```json
  {
    "id": "CVE-2025-29927",
    "title": "Middleware Auth Bypass",
    "severity": "CRITICAL"
  }
  ```
