"""Loopback-only fixture for authorized RedOps Forge smoke tests.

Start with: python examples/safe_lab.py
Never binds to an external interface.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/":
            self.send_error(404)
            return
        data = b"<html><body>Authorized RedOps Forge lab fixture.</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Set-Cookie", "lab_session=example-placeholder; Path=/")
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8001), Handler)
    print("RedOps Forge authorized lab: http://127.0.0.1:8001/", flush=True)
    server.serve_forever()
