#!/usr/bin/env python3
"""
NextSploit — Unified HTTP Transport Session & Raw Evidence Transaction Logging
"""

import re
import sys
import hashlib
import requests
import urllib3
import traceback
from pathlib import Path
from typing import Optional
from urllib3.util import Retry
from requests.adapters import HTTPAdapter

# Disable urllib3 SSL warnings when verify=False is used
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class NextSploitSession(requests.Session):
    """
    Subclass of requests.Session that intercepts all HTTP requests to:
    - Automatically apply rate-limiting/delay via ScanConfig.throttle()
    - Record request/response details for WAF noise ratio calculations
    - Generate raw request+response text files to help manual audit / bypass validation.
    """

    def __init__(self, config):
        super().__init__()
        self.config = config

    def request(self, method, url, *args, **kwargs):
        # Apply rate limiting / delay before making request
        self.config.throttle()
        try:
            resp = super().request(method, url, *args, **kwargs)
            self.config.record_request(resp.status_code, response=resp)
            self.config.log_transaction(
                module_id=self.config.current_module_id or "scan",
                request_obj=resp.request,
                response_obj=resp,
            )
            return resp
        except Exception as e:
            # Treat network exceptions (timeouts/connection drop) as potential WAF block
            self.config.record_request(503)
            # Log transport errors to debug if verbosity >= 2
            if self.config.verbosity >= 2:
                sys.stderr.write(f"[DEBUG] Transport exception: {e}\n")
            raise


def create_session(config) -> NextSploitSession:
    """
    Create a configured NextSploitSession instance.
    """
    session = NextSploitSession(config)
    session.headers.update({
        "User-Agent": config.user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
    })
    if config.proxies:
        session.proxies.update(config.proxies)
    session.verify = config.verify_ssl

    # ─── Auth injection ───────────────────────────────────────────────────
    if getattr(config, "auth_cookie", None):
        # Parse cookie string: "name1=val1; name2=val2"
        for cookie_pair in config.auth_cookie.split(";"):
            cookie_pair = cookie_pair.strip()
            if "=" in cookie_pair:
                cname, _, cval = cookie_pair.partition("=")
                session.cookies.set(cname.strip(), cval.strip())

    if getattr(config, "auth_token", None):
        token = config.auth_token.strip()
        # Accept both "Bearer xxx" and raw token — add Bearer prefix if missing
        if not token.lower().startswith(("bearer ", "basic ", "token ")):
            token = f"Bearer {token}"
        session.headers["Authorization"] = token

    # Retry adapter: back-off on transient errors and rate-limit responses
    retry_strategy = Retry(
        total=3,
        backoff_factor=1.5,              # waits: 1.5s, 3s, 4.5s
        status_forcelist=[429, 503],     # retry these status codes
        respect_retry_after_header=True,  # honour Retry-After
        allowed_methods=["GET", "POST", "HEAD"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://",  adapter)

    # ─── Auth JSON / Form Login handling ───────────────────────────────
    if getattr(config, "auth_json", None):
        load_auth(config, session)

    return session


def _heuristic_csrf(html: str) -> str:
    """Grab the first hidden input or token-like value as CSRF fallback."""
    m = re.search(r'name=["\'](?:csrf|_token|authenticity_token|csrfmiddlewaretoken)["\'][^>]*value=["\']([^"\']+)["\']', html, re.I)
    return m.group(1) if m else ""


def _do_login(config, session, data: dict):
    """Generic login flow: GET login page -> extract CSRF -> POST creds."""
    headers = {"User-Agent": config.user_agent}
    login_url = data.get("url", "")
    if not login_url:
        return

    # 1. GET login page (harvest CSRF + any pre-login cookies)
    try:
        r = session.get(login_url, headers=headers, timeout=15)
        if r.status_code not in (200, 302):
            if config.verbosity >= 1:
                sys.stderr.write(f"[session] Login page returned status {r.status_code}\n")
    except Exception as e:
        if config.verbosity >= 1:
            sys.stderr.write(f"[session] Login GET error: {e}\n")
        return

    # 2. CSRF extraction
    form = {}
    sel = data.get("csrf_extract")
    if sel:
        m = re.search(rf'(?:name|id)=["\']{re.escape(sel)}["\'][^>]*value=["\']([^"\']+)["\']', r.text)
        if m:
            form[sel] = m.group(1)
        else:
            form[sel] = _heuristic_csrf(r.text)
    else:
        csrf_val = _heuristic_csrf(r.text)
        if csrf_val:
            form["_csrf"] = csrf_val

    # 3. Fill credentials
    uname_field = data.get("username_field", "email")
    pword_field = data.get("password_field", "password")
    form[uname_field] = data.get("username", "")
    form[pword_field] = data.get("password", "")

    # 4. POST credentials
    try:
        login_resp = session.post(login_url, data=form, headers=headers, allow_redirects=True, timeout=20)
        cookies = {c.name: c.value for c in session.cookies}
        expected = data.get("session_cookie_names", [])
        if expected:
            got = [c for c in expected if c in cookies]
            if got:
                if config.verbosity >= 1:
                    sys.stderr.write(f"[session] Authenticated successfully (cookies: {got})\n")
                config.auth_mode = "form-login"
            else:
                if config.verbosity >= 1:
                    sys.stderr.write(f"[session] Login POST {login_resp.status_code} but missing expected cookies: {expected}\n")
        elif login_resp.status_code in (200, 302):
            config.auth_mode = "form-login"
    except Exception as e:
        if config.verbosity >= 1:
            sys.stderr.write(f"[session] Login POST failed: {e}\n")


def load_auth(config, session):
    """Populate session with authentication from auth_json."""
    if not getattr(config, "auth_json", None):
        return

    json_path = Path(config.auth_json)
    if not json_path.exists():
        if config.verbosity >= 1:
            sys.stderr.write(f"[session] Auth JSON file not found: {json_path}\n")
        return

    try:
        import json
        data = json.loads(json_path.read_text(encoding="utf-8"))
        if data.get("url"):
            _do_login(config, session, data)
        elif data.get("cookies"):
            for k, v in data["cookies"].items():
                session.cookies.set(k, v)
            config.auth_mode = "json-cookies"
        elif data.get("headers"):
            session.headers.update(data["headers"])
            config.auth_mode = "json-headers"
    except Exception as e:
        if config.verbosity >= 1:
            sys.stderr.write(f"[session] Error parsing auth JSON: {e}\n")


def session_health(config, session) -> bool:
    """Verify session still valid (e.g., auth probe URL returns 200, not redirect)."""
    if not getattr(config, "auth_mode", None):
        return True  # nothing to validate

    probe = getattr(config, "auth_probe_url", "/api/me")
    if not probe:
        return True

    target = config.target.rstrip("/")
    probe_url = f"{target}{probe if probe.startswith('/') else '/' + probe}"

    try:
        r = session.get(probe_url, timeout=10, allow_redirects=False)
        if r.status_code in (301, 302, 401, 403):
            if config.verbosity >= 1:
                sys.stderr.write(f"[session] Auth probe ({probe_url}) returned {r.status_code} — session may be expired\n")
            return False
        return True
    except Exception:
        return False

