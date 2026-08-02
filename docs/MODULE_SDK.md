# NextSploit v4 - Module SDK Guide

## 1. Module Protocol
Every module must implement the `IModule` protocol, containing the 7-step lifecycle methods:

```text
initialize(context)
      │
      ▼
precondition(context) -> bool
      │
      ▼
execute(context)
      │
      ▼
collect(context)
      │
      ▼
validate(context)
      │
      ▼
report(context) -> Any
      │
      ▼
cleanup(context)
```

## 2. Dependencies
Modules define their requirements under preconditions:
- Target router type (`app` or `pages`).
- Target Next.js version constraints.
- Capability requirements (e.g., exposed build ID).
