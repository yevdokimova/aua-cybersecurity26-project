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


def write(source, sql, parsed_query, engine_verdict, blocked, shield_enabled):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    record = AuditRecord(
        id=str(uuid.uuid4()),
        timestamp=time.time(),
        user="demo",
        role="demo",
        source_ip="",
        source_tag=source,
        database="demo",
        query_type=parsed_query.query_type.name,
        raw_sql=sql,
        normalized_sql=parsed_query.normalized_sql,
        ast_fingerprint=parsed_query.ast_fingerprint,
        tables=parsed_query.tables,
        final_action="BLOCKED" if blocked else ("ALLOWED" if shield_enabled else "SHIELD_OFF"),
        engine_results=[{
            "engine":   engine_verdict.engine,
            "action":   engine_verdict.action.name,
            "score":    engine_verdict.score,
            "reasons":  engine_verdict.reasons,
            "rule_ids": engine_verdict.rule_ids,
        }] if engine_verdict else [],
        total_latency_ms=engine_verdict.latency_ms if engine_verdict else 0.0,
        proxy_mode="enforce" if shield_enabled else "monitor",
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
