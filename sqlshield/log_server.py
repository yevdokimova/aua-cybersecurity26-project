import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

from sqlshield import audit

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class LogHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/api/logs":
            body = json.dumps({"logs": audit.read_all()}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        else:
            self._serve_file("logs.html")

    def _serve_file(self, name):
        fp = os.path.join(STATIC_DIR, name)
        if not os.path.isfile(fp):
            self.send_error(404); return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(open(fp, "rb").read())

    def log_message(self, *_):
        pass


def run(port=8080):
    HTTPServer(("", port), LogHandler).serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"Log dashboard → http://localhost:{port}")
    run(port)
