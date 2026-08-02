# NextSploit v4 - Plugin SDK Guide

## 1. Plugin Manifest
Directory-based plugins must define a `manifest.json` file in their folder root:

```json
{
  "id": "next.cve.2025.29927",
  "name": "Middleware Authorization Bypass",
  "version": "1.0.0",
  "sdk_version": "4.0",
  "plugin_version": "1.0.0",
  "phase": "passive",
  "severity": "critical",
  "requires": [
    "middleware",
    "next>=15.0"
  ],
  "policy": [
    "safe",
    "bugbounty"
  ]
}
```

## 2. Dynamic Auto-Registration
Drop a folder under `plugins/` with the manifest and code entry point, and it will be auto-detected and registered in the scan workflow.
