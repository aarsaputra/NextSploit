# NextSploit v4 - Architecture Reference Document

## 1. System Overview
NextSploit v4 transitions to a service-oriented framework. It decouples targets, phases, logic engines, and reporting output.

```
                  [cli.py]
                     │
              [ScanContext]
                     │
             [ScanPipeline]
                     │
           [ServiceContainer]
                     │
   ┌─────────────────┼─────────────────┐
   ▼                 ▼                 ▼
[Reporter]    [EventBus]      [ResourceManager]
```

## 2. Core Architecture Freeze Guidelines
Starting from NextSploit v4.0.0-alpha, the core architecture is considered frozen. 

No new subsystems, engines, registries, or interfaces may be introduced unless:
1. It solves a proven architectural limitation.
2. It passes an Architecture Decision Record (ADR).
3. It does not increase unnecessary coupling.
4. It maintains backward compatibility whenever possible.
