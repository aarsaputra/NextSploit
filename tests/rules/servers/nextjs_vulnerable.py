"""
tests/rules/servers/nextjs_vulnerable.py — Mock vulnerable Next.js middleware server.

Simulates a Next.js application vulnerable to CVE-2025-29927:
  - /dashboard, /admin, /profile → 401 normally
  - /dashboard, /admin, /profile → 200 + x-middleware-next when exploit header present
  - /redirect?next=<url> → 302 to any URL (open redirect)
  - /_next/server/middleware-manifest.json → exposed manifest
"""

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


MIDDLEWARE_MANIFEST = """{
  "version": 2,
  "matchers": [{"regexp": "/(.*)", "originalSource": "/:path*"}],
  "middleware": {"files": ["server/middleware"], "name": "middleware"}
}"""

PROTECTED_PATHS = {"/dashboard", "/admin", "/profile", "/api/protected"}
EXPLOIT_HEADER = "x-middleware-subrequest"
BYPASS_VALUE_FRAGMENT = "middleware:middleware"


class VulnerableNextjsHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        # ── Middleware manifest (information disclosure)
        if path == "/_next/server/middleware-manifest.json":
            self._send_json(200, MIDDLEWARE_MANIFEST)
            return

        # ── Open redirect
        if path in ("/redirect", "/login") and ("next" in params or "redirect" in params):
            target = (params.get("next") or params.get("redirect"))[0]
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return

        # ── Protected route — check exploit header
        if path in PROTECTED_PATHS or any(path.startswith(p) for p in PROTECTED_PATHS):
            bypass_val = self.headers.get(EXPLOIT_HEADER, "")
            if BYPASS_VALUE_FRAGMENT in bypass_val:
                # Vulnerable: exploit header bypasses auth
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("x-middleware-next", "1")
                self.end_headers()
                self.wfile.write(b"<html><body>Dashboard — welcome, authenticated user!</body></html>")
            else:
                # Normal: requires authentication
                self.send_response(401)
                self.send_header("Content-Type", "text/html")
                self.send_header("WWW-Authenticate", "Bearer realm=\"app\"")
                self.end_headers()
                self.wfile.write(b"<html><body>Unauthorized</body></html>")
            return

        # ── Default page
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "Next.js 15.1.0")
        self.end_headers()
        self.wfile.write(b"<html><body>Hello from Next.js</body></html>")

    def _send_json(self, status: int, body: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *args):
        pass  # Suppress server log noise


def start_vulnerable_server(port: int = 0):
    server = HTTPServer(("127.0.0.1", port), VulnerableNextjsHandler)
    actual_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, actual_port
