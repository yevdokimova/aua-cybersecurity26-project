#!/usr/bin/env python3
import json
import os
import sys
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler

import psycopg2
import psycopg2.extras

from sqlshield import audit
from sqlshield.parser import Parser
from sqlshield.engines.signature import SignatureEngine, Rule, Condition, DEFAULT_RULES
from sqlshield.types import Action

# ── Shield ────────────────────────────────────────────────────────────────────

RULES = DEFAULT_RULES + [
    Rule(
        id="SIG-011",
        name="Comment-based injection",
        description="-- or /**/ in a SELECT truncates the WHERE clause (e.g. admin' --).",
        severity="high",
        conditions=[Condition(has_comment=True, query_types=["SELECT"])],
    ),
]

_parser = Parser()
_engine = SignatureEngine(rules=RULES, strictness="medium")
SHIELD_ENABLED = False


def run_shield(sql):
    pq = _parser.parse(sql)
    if not SHIELD_ENABLED:
        return False, None, pq, None
    v = _engine.inspect(pq)
    verdict = "rejected" if v.action == Action.BLOCK else ("suspicious" if v.score > 0 else "accepted")
    detail = "; ".join(v.reasons) if v.reasons else "no issues detected"
    return v.action == Action.BLOCK, {
        "verdict": verdict,
        "stages": [{"stage": "signature", "verdict": verdict, "detail": detail}],
    }, pq, v


# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    return psycopg2.connect(
        host=os.environ.get("DB_HOST", "localhost"),
        port=int(os.environ.get("DB_PORT", 5432)),
        dbname=os.environ.get("DB_NAME", "demo"),
        user=os.environ.get("DB_USER", "demo"),
        password=os.environ.get("DB_PASS", "demo"),
    )


def execute_query(sql, fetch=True):
    pq = _parser.parse(sql)
    if pq.has_stacked and "DROP" in sql.upper():
        return [], None, True
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql)
        rows = [dict(r) for r in cur.fetchall()] if fetch and sql.strip().upper().startswith("SELECT") else []
        conn.commit()
        return rows, None, False
    except Exception as e:
        conn.rollback()
        return [], str(e), False
    finally:
        conn.close()


def init_db():
    for i in range(30):
        try:
            conn = get_db(); break
        except Exception:
            print(f"Waiting for database... ({i+1}/30)")
            time.sleep(2)
    else:
        print("Could not connect to database."); sys.exit(1)

    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, username VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(100) NOT NULL, role VARCHAR(20) NOT NULL DEFAULT 'user');
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL,
            price INTEGER NOT NULL, description TEXT);
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY, name VARCHAR(100), email VARCHAR(100),
            message TEXT, sent_at TIMESTAMP DEFAULT NOW());
        CREATE TABLE IF NOT EXISTS chat_logs (
            id SERIAL PRIMARY KEY, user_message TEXT, created_at TIMESTAMP DEFAULT NOW());
    """)
    cur.execute("""
        DELETE FROM products WHERE id NOT IN (
            SELECT MIN(id) FROM products GROUP BY name);
    """)
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS products_name_unique ON products(name);
    """)
    cur.execute("""
        INSERT INTO users (username, password, role) VALUES
            ('admin','supersecret','superadmin'),('alice','pass123','admin'),
            ('bob','secret','user'),('charlie','charlie99','user')
        ON CONFLICT (username) DO NOTHING;
    """)
    cur.execute("""
        INSERT INTO products (name, price, description) VALUES
            ('Laptop',999,'High-performance laptop'),('Keyboard',49,'Mechanical keyboard'),
            ('Mouse',29,'Wireless mouse'),('Monitor',349,'4K monitor'),
            ('Headphones',79,'Noise-cancelling headphones')
        ON CONFLICT (name) DO NOTHING;
    """)
    conn.commit(); conn.close()
    print("Database ready.")


def get_message_count():
    conn = get_db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM messages")
        return cur.fetchone()[0]
    except Exception:
        return 0
    finally:
        conn.close()


# ── Vulnerable query builders (intentional — demo only) ──────────────────────

def build_search(q):
    return "SELECT * FROM products WHERE name LIKE '%" + q + "%'"

def build_login(u, p):
    return "SELECT * FROM users WHERE username='" + u + "' AND password='" + p + "'"

def build_contact(name, email, msg):
    return "INSERT INTO messages (name, email, message) VALUES ('" + name + "', '" + email + "', '" + msg + "')"

def build_chat(msg):
    return "INSERT INTO chat_logs (user_message) VALUES ('" + msg + "')"


# ── Demo server ───────────────────────────────────────────────────────────────

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class DemoHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        path = "/index.html" if self.path in ("/", "/index.html") else self.path
        fp = os.path.join(STATIC_DIR, path.lstrip("/"))
        if not os.path.isfile(fp):
            self.send_error(404); return
        ct = {"html": "text/html", "css": "text/css", "js": "application/javascript"}.get(
            fp.rsplit(".", 1)[-1], "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", ct)
        self.end_headers()
        self.wfile.write(open(fp, "rb").read())

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        routes = {
            "/api/search":        self._search,
            "/api/login":         self._login,
            "/api/contact":       self._contact,
            "/api/chat":          self._chat,
            "/api/shield/toggle": self._toggle,
            "/api/shield/reset":  lambda d: self._json({"reset": True}),
        }
        fn = routes.get(self.path)
        if fn: fn(data)
        else: self.send_error(404)

    def _toggle(self, data):
        global SHIELD_ENABLED
        SHIELD_ENABLED = data.get("enabled", False)
        self._json({"shield_enabled": SHIELD_ENABLED})

    def _search(self, data):
        sql = build_search(data.get("query", ""))
        blocked, shield, pq, ev = run_shield(sql)
        audit.write("search", sql, pq, ev, blocked, SHIELD_ENABLED)
        if blocked:
            self._json({"blocked": True, "shield": shield, "query": sql, "results": [], "result_count": 0}); return
        rows, _, _ = execute_query(sql)
        self._json({"blocked": False, "shield": shield, "query": sql, "results": rows, "result_count": len(rows)})

    def _login(self, data):
        sql = build_login(data.get("username", ""), data.get("password", ""))
        blocked, shield, pq, ev = run_shield(sql)
        audit.write("login", sql, pq, ev, blocked, SHIELD_ENABLED)
        if blocked:
            self._json({"blocked": True, "shield": shield, "query": sql, "success": False, "message": "Blocked by Shield."}); return
        rows, _, _ = execute_query(sql)
        if rows:
            u = rows[0]
            self._json({"blocked": False, "shield": shield, "query": sql, "success": True,
                        "message": f"Logged in as: {u['username']} (role: {u['role']})", "user": dict(u)})
        else:
            self._json({"blocked": False, "shield": shield, "query": sql, "success": False, "message": "Invalid credentials."})

    def _contact(self, data):
        sql = build_contact(data.get("name", ""), data.get("email", ""), data.get("message", ""))
        blocked, shield, pq, ev = run_shield(sql)
        audit.write("contact", sql, pq, ev, blocked, SHIELD_ENABLED)
        if blocked:
            self._json({"blocked": True, "shield": shield, "query": sql, "success": False, "message": "Blocked by Shield."}); return
        _, err, dropped = execute_query(sql, fetch=False)
        msg = "DANGER: would have dropped the table!" if dropped else ("Database error: " + err if err else f"Message saved. Total: {get_message_count()}")
        self._json({"blocked": False, "shield": shield, "query": sql, "success": not (dropped or err), "message": msg})

    def _chat(self, data):
        msg = data.get("message", "")
        sql = build_chat(msg)
        blocked, shield, pq, ev = run_shield(sql)
        audit.write("chat", sql, pq, ev, blocked, SHIELD_ENABLED)
        if blocked:
            self._json({"blocked": True, "shield": shield, "query": sql, "reply": "Blocked by Shield."}); return
        execute_query(sql, fetch=False)
        self._json({"blocked": False, "shield": shield, "query": sql, "reply": _bot_reply(msg)})

    def _json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def _bot_reply(msg):
    m = msg.lower()
    if any(w in m for w in ("hello", "hi")): return "Hello! How can I help?"
    if "help" in m: return "I can help with products, orders, or general questions."
    if "order" in m: return "Share your order number and I'll look it up."
    if "price" in m: return "Check our product catalog for latest prices!"
    if any(w in m for w in ("bye", "thanks")): return "You're welcome! Have a great day."
    return "Thanks for your message. Let me look into that."


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()

    app_port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 8000

    server = HTTPServer(("", app_port), DemoHandler)
    print(f"Demo app      → http://localhost:{app_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
