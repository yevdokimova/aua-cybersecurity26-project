from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request


LLM_HOST    = os.environ.get("LLM_HOST",  "http://llm:11434")
LLM_MODEL   = os.environ.get("LLM_MODEL", "llama3.2:3b")
LLM_TIMEOUT = float(os.environ.get("LLM_TIMEOUT", "60"))


SCHEMA_DOC = """\
Tables (PostgreSQL):

  users(id, username, password, role)
      -- SENSITIVE. Never SELECT password. Never query without a WHERE.
  products(id, name, price, description)
  messages(id, name, email, message, sent_at)
  chat_logs(id, user_message, created_at)
"""

SYSTEM_PROMPT = (
    "You are a read-only SQL assistant for a small PostgreSQL demo store.\n"
    "Reply with ONE single SQL statement, nothing else.\n"
    "Wrap the SQL in a ```sql fenced code block.\n"
    "Rules you MUST follow:\n"
    "  - SELECT only. No INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, GRANT.\n"
    "  - Always include a LIMIT clause (max 50 rows).\n"
    "  - Never query the `users` table without a WHERE clause.\n"
    "  - Never SELECT the `password` column.\n"
    "  - Use only the tables and columns described in the schema.\n"
    "  - No UNION, no stacked statements, no comments.\n"
    f"\nSchema:\n{SCHEMA_DOC}"
)


def generate_sql(user_message: str) -> tuple[str, str]:
    prompt = (
        "User question: " + user_message.strip() + "\n\n"
        "Write the SQL query that answers it."
    )
    body = json.dumps({
        "model":  LLM_MODEL,
        "system": SYSTEM_PROMPT,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 256},
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{LLM_HOST.rstrip('/')}/api/generate",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=LLM_TIMEOUT) as resp:
            payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return ("SELECT 1",
                f"[LLM unavailable: {exc}. Returning a no-op query.]")

    raw = payload.get("response", "").strip()
    sql = _extract_sql(raw)
    return sql, raw


_FENCE_RE = re.compile(r"```(?:sql)?\s*(.+?)\s*```", re.DOTALL | re.IGNORECASE)


def _extract_sql(text: str) -> str:
    m = _FENCE_RE.search(text)
    candidate = (m.group(1) if m else text).strip()
    while candidate.endswith(";"):
        candidate = candidate[:-1].rstrip()
    return candidate or "SELECT 1"
