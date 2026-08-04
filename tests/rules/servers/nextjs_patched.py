"""
tests/rules/servers/nextjs_patched.py — Mock patched/secure Next.js server.

Simulates a Next.js application running version 15.2.4 (patched against CVE-2025-29927):
  - /dashboard, /admin, /profile → 401 Unauthorized regardless of x-middleware-subrequest header
  - /redirect?next=<url> → 400 Bad Request or safe local redirect (rejects external domains)
  - /_next/server/middleware-manifest.json → 404 Not Found
"""

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs


PROTECTED_PATHS = {"/dashboard", "/admin", "/profile", "/api/protected"}


class PatchedNextjsHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        # ── Manifest is hidden/protected in patched build
        if path == "/_next/server/middleware-manifest.json":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            return

        # ── Open redirect defense — rejects external target domains
        if path in ("/redirect", "/login") and ("next" in params or "redirect" in params):
            target = (params.get("next") or params.get("redirect"))[0]
            if target.startswith("http://") or target.startswith("https://"):
                # Patched behavior: reject external domain redirects
                self.send_response(400)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(b"400 Invalid redirect target")
                return
            else:
                self.send_response(302)
                self.send_header("Location", target)
                self.end_headers()
                return

        # ── Protected route — patched version strictly validates auth regardless of header
        if path in PROTECTED_PATHS or any(path.startswith(p) for p in PROTECTED_PATHS):
            self.send_response(401)
            self.send_header("Content-Type", "text/html")
            self.send_header("WWW-Authenticate", "Bearer realm=\"app\"")
            self.end_headers()
            self.wfile.write(b"<html><body>Unauthorized</body></html>")
            return

        # ── Default page
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "Next.js 15.2.4")
        self.end_headers()
        self.wfile.write(b"<html><body>Hello from Patched Next.js 15.2.4</body></html>")

    def log_message(self, *args):
        pass  # Suppress server log noise


def start_patched_server(port: int = 0):
    server = HTTPServer(("127.0.0.1", port), PatchedNextjsHandler)
    actual_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, actual_port
