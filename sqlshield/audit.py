import json
import os
import threading
import time
import uuid
from dataclasses import asdict

from .types import AuditRecord

LOG_FILE = os.environ.get(
    "AUDIT_LOG",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs", "audit.jsonl"),
)
_lock = threading.Lock()


def write(source, sql, parsed_query, blocked, shield_enabled,
          engine_verdict=None, engine_verdicts=None, proxy_mode=None):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

    ctx = getattr(parsed_query, "context", None)
    if ctx is not None:
        user       = ctx.session.user
        role       = ctx.role
        source_ip  = ctx.session.source_ip
        source_tag = ctx.source_tag if ctx.source_tag != "unknown" else source
        database   = ctx.session.database or "demo"
    else:
        user, role, source_ip = "demo", "demo", ""
        source_tag, database = source, "demo"

    if engine_verdicts is None:
        engine_verdicts = [engine_verdict] if engine_verdict else []
    engine_results = [
        {
            "engine":   v.engine,
            "action":   v.action.name,
            "score":    v.score,
            "reasons":  v.reasons,
            "rule_ids": v.rule_ids,
        }
        for v in engine_verdicts if v is not None
    ]
    total_latency = sum((v.latency_ms for v in engine_verdicts if v is not None), 0.0)

    record = AuditRecord(
        id=str(uuid.uuid4()),
        timestamp=time.time(),
        user=user,
        role=role,
        source_ip=source_ip,
        source_tag=source_tag,
        database=database,
        query_type=parsed_query.query_type.name,
        raw_sql=sql,
        normalized_sql=parsed_query.normalized_sql,
        ast_fingerprint=parsed_query.ast_fingerprint,
        tables=parsed_query.tables,
        final_action="BLOCKED" if blocked else ("ALLOWED" if shield_enabled else "SHIELD_OFF"),
        engine_results=engine_results,
        total_latency_ms=total_latency,
        proxy_mode=proxy_mode or ("enforce" if shield_enabled else "monitor"),
    )
    with _lock:
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(asdict(record)) + "\n")


def read_all():
    if not os.path.exists(LOG_FILE):
        return []
    with _lock:
        with open(LOG_FILE) as f:
            lines = f.readlines()
    result = []
    for line in lines:
        line = line.strip()
        if line:
            try:
                result.append(json.loads(line))
            except Exception:
                pass
    return result
