# NextSploit v4 - Versioning Strategy

## 1. Core Framework
The core framework uses standard Semantic Versioning (SemVer) `MAJOR.MINOR.PATCH`:
- **MAJOR**: Breaking changes to core protocols (`IModule`, `ScanContext`, container bindings).
- **MINOR**: New features, new CLI capabilities, or new interfaces.
- **PATCH**: Bug fixes, performance tuning, and logic updates.

## 2. Plugin & SDK Version Bounds
Plugins declare compatible version constraints using `"sdk_version"` boundaries (e.g. `sdk_version: ">=4.0.0, <5.0.0"`). The plugin loader rejects incompatible versions.
