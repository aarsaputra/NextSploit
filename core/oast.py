#!/usr/bin/env python3
"""
core/oast.py — Out-of-Band Application Security Testing (OAST).

Bundles a self-hosted callback listener (HTTP + DNS fallback) and an optional
interactsh client so SSRF/OOB findings become proven.
"""

import queue
import random
import socket
import string
import threading
import time
from typing import Optional, Union, Dict, Any
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import requests

try:
    import dnslib  # type: ignore
    HAS_DNSLIB = True
except ImportError:
    HAS_DNSLIB = False

try:
    import pyinteractsh  # type: ignore
    HAS_INTERACTSH = True
except ImportError:
    HAS_INTERACTSH = False


class OastServer:
    """Self-hosted callback listener (HTTP on random high port + optional DNS)."""

    def __init__(self, listen_host: str = "0.0.0.0", http_port: int = 0):
        self.hits = queue.Queue()
        self.collaborator_id = "".join(random.choices(
            string.ascii_lowercase + string.digits, k=8))
        self.http_port = http_port
        self.httpd: Optional[ThreadingHTTPServer] = None
        self.dns_sock: Optional[socket.socket] = None
        self._threads = []

    class _Handler(BaseHTTPRequestHandler):
        def _record(self):
            body_len = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(body_len).decode(errors="replace") if body_len else ""
            self.server.hits.put({
                "type": "http",
                "path": self.path,
                "headers": dict(self.headers),
                "body": body[:512],
                "time": time.time(),
            })
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        do_GET = _record
        do_POST = _record
        do_PUT = _record
        do_HEAD = _record
        log_message = lambda *a: None

    def start(self):
        """Start HTTP server and optional DNS listener."""
        try:
            self.httpd = ThreadingHTTPServer(("0.0.0.0", self.http_port), self._Handler)
            self.httpd.hits = self.hits  # attach queue
            self.http_port = self.httpd.server_address[1]
            t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
            t.start()
            self._threads.append(t)
        except Exception:
            return

        if HAS_DNSLIB:
            try:
                from dnslib import A, RR, DNSRecord
                self.dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.dns_sock.bind(("0.0.0.0", 53))

                def dns_loop():
                    while True:
                        try:
                            data, addr = self.dns_sock.recvfrom(512)
                            req = DNSRecord.parse(data)
                            qname = str(req.q.qname)
                            self.hits.put({"type": "dns", "qname": qname, "time": time.time()})
                            reply = req.reply()
                            reply.add_answer(RR(qname, rdata=A("127.0.0.1"), ttl=1))
                            self.dns_sock.sendto(reply.pack(), addr)
                        except Exception:
                            break

                t2 = threading.Thread(target=dns_loop, daemon=True)
                t2.start()
                self._threads.append(t2)
            except Exception:
                pass  # DNS on port 53 requires root — HTTP-only fallback

    def http_url(self, token: str = "") -> str:
        pub_ip = self._public_ip()
        if pub_ip:
            return f"http://{pub_ip}:{self.http_port}/{token}"
        return f"http://127.0.0.1:{self.http_port}/{token}"

    def dns_domain(self, token: str = "") -> str:
        return f"{token}.{self.collaborator_id}.oast.local"

    @staticmethod
    def _public_ip() -> str:
        try:
            return requests.get("https://api.ipify.org", timeout=4).text.strip()
        except Exception:
            return ""

    def wait_for_hit(self, token: str, timeout: float = 20.0) -> Optional[Dict[str, Any]]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                hit = self.hits.get(timeout=1)
            except queue.Empty:
                continue

            hit_str = str(hit.get("path", "")) + str(hit.get("qname", ""))
            if token in hit_str:
                return hit
        return None

    def shutdown(self):
        if self.httpd:
            try:
                self.httpd.shutdown()
            except Exception:
                pass
        if self.dns_sock:
            try:
                self.dns_sock.close()
            except Exception:
                pass


class InteractshClient:
    """Wrapper for interactsh service."""

    def __init__(self, token_file: str = ".interactsh-token"):
        self.token_file = token_file
        self.client = None

    def start() -> bool:
        if not HAS_INTERACTSH:
            return False
        try:
            from pyinteractsh import Interactsh  # type: ignore
            self.client = Interactsh(server="oast.pro", token=self._load_token())
            self.client.register()
            self._save_token()
            return True
        except Exception:
            return False

    def url(self, token: str = "x") -> Optional[str]:
        return f"http://{token}.{self.client.domain}" if self.client else None

    def poll(self, token: str, timeout: float = 20.0) -> Optional[Dict[str, Any]]:
        if not self.client:
            return None
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                for record in self.client.poll_once():
                    if token in str(record.get("full-id", "")):
                        return record
            except Exception:
                pass
            time.sleep(1)
        return None

    def _load_token(self) -> Optional[str]:
        try:
            with open(self.token_file, "r") as f:
                return f.read().strip()
        except Exception:
            return None

    def _save_token(self):
        if self.client and getattr(self.client, "token", None):
            try:
                with open(self.token_file, "w") as f:
                    f.write(self.client.token)
            except Exception:
                pass


def get_oast(config) -> Optional[Union[OastServer, InteractshClient]]:
    """Factory to initialize self-hosted OAST server or Interactsh client."""
    server = OastServer()
    server.start()
    if server.http_port > 0:
        config.oast = server
        if getattr(config, "verbosity", 0) >= 1:
            import sys
            sys.stderr.write(f"[oast] Callback listener ready on :{server.http_port} (id={server.collaborator_id})\n")
        return server
    return None
