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
  products(id, name, price, description)
  messages(id, name, email, message, sent_at)
  chat_logs(id, user_message, created_at)
  users(id, username, password, role)  -- SENSITIVE: never SELECT password, never query without WHERE
"""

_SQL_SYSTEM = (
    "You are a SQL generator for a PostgreSQL demo store.\n"
    "Reply with ONLY a single SELECT query inside a ```sql block. No other text.\n"
    "Rules:\n"
    "  - SELECT only. No INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, GRANT.\n"
    "  - Always include LIMIT (max 50 rows).\n"
    "  - Never query the users table without a WHERE clause.\n"
    "  - Never SELECT the password column.\n"
    "  - Use only the tables listed in the schema.\n"
    "  - No UNION, no stacked statements, no SQL comments.\n"
    "  - Use ILIKE instead of LIKE for case-insensitive text searches.\n"
    f"\nSchema:\n{SCHEMA_DOC}"
)

_CHAT_SYSTEM = (
    "You are a friendly assistant for a demo online store. "
    "Reply conversationally in 1-3 sentences. "
    "Never generate SQL or use code blocks."
)

# Patterns that are clearly conversational — everything else goes to SQL mode
_CHAT_RE = re.compile(
    r"^\s*(hi+|hey+|hello|howdy|greetings|good\s+(morning|afternoon|evening)|"
    r"how are you|how's it going|what's up|thank(s| you)|bye|goodbye|"
    r"what can you do|help me|who are you)\W*$",
    re.IGNORECASE,
)


def generate_response(user_message: str) -> tuple[str | None, str, str]:
    """Return (sql_or_none, text_reply, raw_llm_output).

    sql_or_none is set when the message is a data query;
    text_reply carries the conversational response otherwise.
    """
    if _CHAT_RE.match(user_message):
        return _chat_response(user_message)
    return _sql_response(user_message)


def _sql_response(user_message: str) -> tuple[str | None, str, str]:
    raw = _call_llm(_SQL_SYSTEM, "Query: " + user_message.strip())
    sql = _extract_sql(raw)
    if sql:
        return sql, "", raw
    # Model returned text instead of SQL — fall back to conversational reply
    return None, raw or "I couldn't generate a query for that.", raw


def _chat_response(user_message: str) -> tuple[str | None, str, str]:
    raw = _call_llm(_CHAT_SYSTEM, user_message.strip())
    return None, raw or "I'm not sure how to answer that.", raw


def _call_llm(system: str, prompt: str) -> str:
    body = json.dumps({
        "model":   LLM_MODEL,
        "system":  system,
        "prompt":  prompt,
        "stream":  False,
        "options": {"temperature": 0.3, "num_predict": 300},
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
        return payload.get("response", "").strip()
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        return f"I'm having trouble reaching my backend right now ({exc}). Please try again."


_FENCE_RE = re.compile(r"```(?:sql)?\s*(.+?)\s*```", re.DOTALL | re.IGNORECASE)


def _extract_sql(text: str) -> str | None:
    m = _FENCE_RE.search(text)
    if not m:
        return None
    candidate = m.group(1).strip()
    while candidate.endswith(";"):
        candidate = candidate[:-1].rstrip()
    return candidate or None
