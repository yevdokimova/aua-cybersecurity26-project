import json
import os
import sys
from dataclasses import asdict
from http.server import HTTPServer, BaseHTTPRequestHandler

from sqlshield import audit
from sqlshield.allowlist import AllowlistEntry, default_store

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

_ALLOWLIST_PREFIX = "/api/allowlist"


class LogHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/api/logs":
            return self._json(200, {"logs": audit.read_all()})
        if self.path == _ALLOWLIST_PREFIX:
            return self._json(200, {
                "entries": [asdict(e) for e in default_store.list_all()],
            })
        if self.path.startswith(_ALLOWLIST_PREFIX + "/"):
            fp = self.path[len(_ALLOWLIST_PREFIX) + 1:]
            entry = default_store.get(fp)
            if entry is None:
                return self._json(404, {"error": "not found"})
            return self._json(200, asdict(entry))
        self._serve_file("logs.html")

    def do_POST(self):
        if self.path != _ALLOWLIST_PREFIX:
            return self._json(404, {"error": "not found"})
        body = self._read_body()
        fp = (body.get("fingerprint") or "").strip()
        if not fp:
            return self._json(400, {"error": "fingerprint is required"})
        entry = AllowlistEntry(
            fingerprint=fp,
            raw_sql_example=body.get("raw_sql_example", ""),
            normalized_sql=body.get("normalized_sql", ""),
            added_by=body.get("added_by", "admin"),
            reason=body.get("reason", ""),
        )
        if not default_store.add(entry):
            return self._json(409, {"error": "fingerprint already allowlisted"})
        return self._json(201, asdict(entry))

    def do_DELETE(self):
        if not self.path.startswith(_ALLOWLIST_PREFIX + "/"):
            return self._json(404, {"error": "not found"})
        fp = self.path[len(_ALLOWLIST_PREFIX) + 1:]
        if not default_store.remove(fp):
            return self._json(404, {"error": "not found"})
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def _serve_file(self, name):
        fp = os.path.join(STATIC_DIR, name)
        if not os.path.isfile(fp):
            self.send_error(404); return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(open(fp, "rb").read())

    def _json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            return {}

    def log_message(self, *_):
        pass


def run(port=8080):
    HTTPServer(("", port), LogHandler).serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    print(f"Log dashboard \u2192 http://localhost:{port}")
    run(port)
