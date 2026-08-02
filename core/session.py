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
    })
    if config.proxies:
        session.proxies.update(config.proxies)
    session.verify = config.verify_ssl

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

    return session
