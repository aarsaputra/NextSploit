# NextSploit v4 - Policy Engine Specification

## 1. Introduction
The Policy Engine regulates the execution context of the scan. Instead of passing dozens of flags, a scan profile `--policy` is specified.

## 2. Policy Matrix

| Policy | Passive Scanning | Active Testing | Upload Testing | Replay Validation |
|---|---|---|---|---|
| **safe** | Yes | No | No | No |
| **bugbounty** | Yes | Safe Level Only | No | Yes |
| **pentest** | Yes | Full (Safe/Moderate) | Yes (Sandbox) | Yes |
| **ci** | Yes | Regression only | No | No |
