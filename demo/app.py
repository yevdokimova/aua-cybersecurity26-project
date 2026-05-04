#!/usr/bin/env python3
import json
import os
import sys
import time
import urllib.request
from http.server import HTTPServer, BaseHTTPRequestHandler

import psycopg2
import psycopg2.extras

from sqlshield.parser import Parser
from demo import llm as llm_client

SHIELD_ENABLED = False
_parser = Parser()

ADMIN_URL = "http://{}:{}".format(
    os.environ.get("ADMIN_HOST", "proxy"),
    os.environ.get("ADMIN_PORT", "9090"),
)


# ── Database ──────────────────────────────────────────────────────────────────

def get_db():
    return psycopg2.connect(
        host=os.environ.get("PROXY_HOST", "proxy"),
        port=int(os.environ.get("PROXY_PORT", 6432)),
        dbname=os.environ.get("DB_NAME", "demo"),
        user=os.environ.get("DB_USER", "demo"),
        password=os.environ.get("DB_PASS", "demo"),
    )


def get_db_as(application_name: str):
    # application_name flows through the proxy enricher → source_tag="ai-agent" → LLMPolicyEngine
    return psycopg2.connect(
        host=os.environ.get("PROXY_HOST", "proxy"),
        port=int(os.environ.get("PROXY_PORT", 6432)),
        dbname=os.environ.get("DB_NAME", "demo"),
        user=os.environ.get("DB_USER", "demo"),
        password=os.environ.get("DB_PASS", "demo"),
        application_name=application_name,
    )


def _shield_result(blocked: bool) -> dict | None:
    if not SHIELD_ENABLED and not blocked:
        return None
    if blocked:
        return {"verdict": "rejected", "stages": [
            {"stage": "proxy", "verdict": "rejected",
             "detail": "blocked by SQLShield", "score": 1.0}
        ]}
    return {"verdict": "accepted", "stages": [
        {"stage": "proxy", "verdict": "accepted",
         "detail": "no issues detected", "score": 0.0}
    ]}


def execute_query(sql, fetch=True):
    pq = _parser.parse(sql)
    if pq.has_stacked and "DROP" in sql.upper() and not SHIELD_ENABLED:
        return [], "demo safety net: stacked DROP simulated, not executed", False
    conn = get_db()
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql)
        rows = [dict(r) for r in cur.fetchall()] if fetch and sql.strip().upper().startswith("SELECT") else []
        conn.commit()
        return rows, None, False
    except Exception as e:
        conn.rollback()
        blocked = getattr(e, "pgcode", None) == "42501"
        return [], str(e), blocked
    finally:
        conn.close()


def execute_ai_query(sql, application_name):
    pq = _parser.parse(sql)
    if pq.has_stacked and "DROP" in sql.upper():
        return [], "demo safety net: stacked DROP simulated, not executed", True
    conn = get_db_as(application_name)
    try:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(sql)
        rows = [dict(r) for r in cur.fetchall()] if (
            sql.strip().upper().startswith("SELECT")
        ) else []
        conn.commit()
        return rows, None, False
    except Exception as e:
        conn.rollback()
        blocked = getattr(e, "pgcode", None) == "42501"
        return [], str(e), blocked
    finally:
        conn.close()


def _call_admin(path: str, payload: dict) -> dict:
    try:
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{ADMIN_URL}{path}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            return json.loads(resp.read())
    except Exception:
        return {}


def init_db():
    for i in range(30):
        try:
            conn = get_db(); break
        except Exception:
            print(f"Waiting for proxy/database... ({i+1}/30)")
            time.sleep(2)
    else:
        print("Could not connect to proxy/database."); sys.exit(1)

    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, username VARCHAR(50) NOT NULL UNIQUE,
            password VARCHAR(100) NOT NULL, role VARCHAR(20) NOT NULL DEFAULT 'user')
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS products (
            id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL,
            price INTEGER NOT NULL, description TEXT)
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY, name VARCHAR(100), email VARCHAR(100),
            message TEXT, sent_at TIMESTAMP DEFAULT NOW())
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_logs (
            id SERIAL PRIMARY KEY, user_message TEXT, created_at TIMESTAMP DEFAULT NOW())
    """)
    cur.execute("""
        DELETE FROM products WHERE id NOT IN (
            SELECT MIN(id) FROM products GROUP BY name)
    """)
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS products_name_unique ON products(name)
    """)
    cur.execute("""
        INSERT INTO users (username, password, role) VALUES
            ('admin','supersecret','superadmin'),('alice','pass123','admin'),
            ('bob','secret','user'),('charlie','charlie99','user')
        ON CONFLICT (username) DO NOTHING
    """)
    cur.execute("""
        INSERT INTO products (name, price, description) VALUES
            ('Laptop',999,'High-performance laptop'),('Keyboard',49,'Mechanical keyboard'),
            ('Mouse',29,'Wireless mouse'),('Monitor',349,'4K monitor'),
            ('Headphones',79,'Noise-cancelling headphones')
        ON CONFLICT (name) DO NOTHING
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
            "/api/shield/reset":  self._reset,
        }
        fn = routes.get(self.path)
        if fn: fn(data)
        else: self.send_error(404)

    def _toggle(self, data):
        global SHIELD_ENABLED
        SHIELD_ENABLED = data.get("enabled", False)
        mode = "enforce" if SHIELD_ENABLED else "monitor"
        _call_admin("/api/v1/mode", {"mode": mode})
        self._json({"shield_enabled": SHIELD_ENABLED})

    def _reset(self, data):
        result = _call_admin("/api/v1/baselines/reset", {"user": "demo"})
        self._json({"reset": True, "anomaly_baseline_cleared": result.get("reset", False)})

    def _search(self, data):
        sql = build_search(data.get("query", ""))
        rows, err, blocked = execute_query(sql)
        shield = _shield_result(blocked)
        if blocked:
            self._json({"blocked": True, "shield": shield, "query": sql, "results": [], "result_count": 0}); return
        self._json({"blocked": False, "shield": shield, "query": sql, "results": rows, "result_count": len(rows)})

    def _login(self, data):
        sql = build_login(data.get("username", ""), data.get("password", ""))
        rows, err, blocked = execute_query(sql)
        shield = _shield_result(blocked)
        if blocked:
            self._json({"blocked": True, "shield": shield, "query": sql, "success": False, "message": "Blocked by Shield."}); return
        if rows:
            u = rows[0]
            self._json({"blocked": False, "shield": shield, "query": sql, "success": True,
                        "message": f"Logged in as: {u['username']} (role: {u['role']})", "user": dict(u)})
        else:
            self._json({"blocked": False, "shield": shield, "query": sql, "success": False, "message": "Invalid credentials."})

    def _contact(self, data):
        sql = build_contact(data.get("name", ""), data.get("email", ""), data.get("message", ""))
        _, err, blocked = execute_query(sql, fetch=False)
        shield = _shield_result(blocked)
        if blocked:
            self._json({"blocked": True, "shield": shield, "query": sql, "success": False, "message": "Blocked by Shield."}); return
        msg = "DANGER: would have dropped the table!" if err and "safety net" in err else ("Database error: " + err if err else f"Message saved. Total: {get_message_count()}")
        self._json({"blocked": False, "shield": shield, "query": sql, "success": not err, "message": msg})

    def _chat(self, data):
        msg = data.get("message", "")
        # classic injection surface: INSERT raw message into chat_logs
        log_sql = build_chat(msg)
        _, log_err, log_blocked = execute_query(log_sql, fetch=False)
        if log_blocked:
            self._json({"blocked": True, "shield": _shield_result(True),
                        "query": log_sql,
                        "reply": "Blocked by Shield (chat-log INSERT)."})
            return

        ai_sql, text_reply, raw = llm_client.generate_response(msg)

        # Conversational response — no SQL to run
        if ai_sql is None:
            self._json({"blocked": False, "shield": None, "query": None,
                        "raw": raw, "reply": text_reply, "results": []})
            return

        # SQL response — run through proxy so LLMPolicyEngine activates
        ai_app_name = f"ai-agent/{llm_client.LLM_MODEL}"
        rows, err, ai_blocked = execute_ai_query(ai_sql, ai_app_name)
        shield = _shield_result(ai_blocked)

        if ai_blocked:
            self._json({
                "blocked": True,
                "shield":  shield,
                "query":   ai_sql,
                "raw":     raw,
                "reply":   "Shield blocked the AI-generated query. "
                           "See the dashboard for which policy fired.",
            })
            return

        reply = _format_chat_reply(msg, ai_sql, rows, err, raw)
        self._json({
            "blocked": False,
            "shield":  shield,
            "query":   ai_sql,
            "raw":     raw,
            "reply":   reply,
            "results": rows,
        })

    def _json(self, data):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def _format_chat_reply(user_msg, sql, rows, err, raw):
    if err:
        return f"Database error while running my query: {err}"
    if not rows:
        return "I ran a query but it returned no rows."
    preview = []
    for r in rows[:5]:
        preview.append(", ".join(f"{k}={v}" for k, v in r.items()))
    suffix = "" if len(rows) <= 5 else f"\n... ({len(rows) - 5} more rows)"
    return "Here's what I found:\n" + "\n".join(preview) + suffix


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    _call_admin("/api/v1/mode", {"mode": "enforce" if SHIELD_ENABLED else "monitor"})

    app_port = int(sys.argv[sys.argv.index("--port") + 1]) if "--port" in sys.argv else 8000

    server = HTTPServer(("", app_port), DemoHandler)
    print(f"Demo app      → http://localhost:{app_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
