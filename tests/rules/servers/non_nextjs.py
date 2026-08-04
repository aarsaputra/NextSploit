"""
tests/rules/servers/non_nextjs.py — Mock non-Next.js server (Express/Django simulation).

Used for testing `MockMode.UNKNOWN` or non-matching technologies (e.g. Express/Laravel/Django)
to ensure RuleFilter correctly skips technology-specific rules without false positives or errors.
"""

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler


class NonNextjsHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("X-Powered-By", "Express")
            self.send_header("Server", "nginx/1.18.0")
            self.end_headers()
            self.wfile.write(b"<html><body>Express Application</body></html>")
            return

        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"404 Not Found")

    def log_message(self, *args):
        pass


def start_non_nextjs_server(port: int = 0):
    server = HTTPServer(("127.0.0.1", port), NonNextjsHandler)
    actual_port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, actual_port
