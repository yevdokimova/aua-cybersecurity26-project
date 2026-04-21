# SQL Shield

A defensive SQL inspection layer with a deliberately vulnerable demo
application and a real-time audit dashboard. Built for the AUA
Cybersecurity 2026 course project.

The goal of the project is to demonstrate, end-to-end, how a small
library can intercept SQL produced by an unsafe application, extract
structural features from it, and decide whether to allow or block it
before it reaches the database.


## Architecture

```
    +------------+     SQL string      +------------------+
    |  Demo app  |  ---------------->  |     Parser       |  sqlglot AST + 11 features
    | (port 8000)|                     +---------+--------+
    +------------+                               |
          ^                                      v
          |                              +-------+--------+
          |                              |    Enricher    |  attaches SessionInfo
          |                              +-------+--------+
          |                                      v
          |                              +-------+--------+
          |     final verdict            |   Aggregator   |  runs engines in parallel
          | <----------------------------+--------+-------+
          |                                       |
          |                          +------------+------------+
          |                          |                         |
          |                  +-------+-------+        +--------+--------+
          |                  | SignatureEng. |        |  AnomalyEngine  |
          |                  | (10+1 rules)  |        | (per-user base) |
          |                  +-------+-------+        +--------+--------+
          |                          |                         |
          v                          v                         v
    +------------+              +-------------------------------+
    | PostgreSQL | <-----+      |        Audit logger           |
    | (port 5432)|       |      |        JSONL records          |
    +------------+       |      +---------------+---------------+
                         |                      |
                         |                      v
                         |              +---------------+
                         +--------------+   Dashboard   |  http://localhost:8080
                                        | (port 8080)   |
                                        +---------------+
```

- `sqlshield/` — the library. No web framework dependency, only `sqlglot`.
- `demo/` — an intentionally vulnerable HTTP application that uses
  `sqlshield` as an in-process firewall. Stdlib HTTP server, psycopg2.
- `sqlshield/log_server.py` — a separate dashboard service that reads
  the shared audit log file and renders it.


## Components

| Module | Responsibility |
|--------|----------------|
| [sqlshield/parser.py](sqlshield/parser.py)            | sqlglot-based AST parser, regex fallback, 11 structural features, normalized fingerprint |
| [sqlshield/enricher.py](sqlshield/enricher.py)        | Attaches `SessionInfo` / `QueryContext` and infers `source_tag` |
| [sqlshield/engines/signature.py](sqlshield/engines/signature.py) | 10 default rules + SIG-011 (auth-bypass comment), strictness floors, fingerprint allowlist |
| [sqlshield/engines/anomaly.py](sqlshield/engines/anomaly.py)     | Per-user statistical baseline (z-score), JSON persistence |
| [sqlshield/verdict.py](sqlshield/verdict.py)          | Aggregates engine verdicts; supports `enforce` / `monitor` / `learning` modes |
| [sqlshield/allowlist.py](sqlshield/allowlist.py)      | Persistent fingerprint allowlist with thread-safe writes |
| [sqlshield/audit.py](sqlshield/audit.py)              | JSONL audit logger, one record per query |
| [sqlshield/log_server.py](sqlshield/log_server.py)    | Audit dashboard with summary cards, filters, and the allowlist UI |
| [demo/app.py](demo/app.py)                            | Vulnerable demo HTTP app (search/login/contact/chat) |


## Running the stack

```bash
docker compose up --build
```

| URL | What it is |
|-----|------------|
| http://localhost:8000 | Vulnerable demo application |
| http://localhost:8080 | Audit log dashboard |
| http://localhost:5050 | pgAdmin (admin@demo.com / admin) |
| postgres://demo:demo@localhost:5432/demo | The Postgres backend |

On first start the `app` service waits for Postgres, creates the
schema, and inserts the seed data (4 users, 5 products).


## Demo walkthrough

1. Open the demo at http://localhost:8000. The shield toggle in the
   nav bar starts in the OFF position.
2. With the shield OFF, run any of the prebuilt attack buttons on the
   home page. The attack succeeds and the dashboard records it as
   `SHIELD_OFF`.
3. Toggle the shield ON and rerun the same attack. The library blocks
   the query, the UI shows which rule fired, and the dashboard records
   it as `BLOCKED` with the rule IDs and a non-zero score.
4. Run a normal query (search "Laptop", log in as `alice` / `pass123`).
   Both go through whether the shield is on or off.

### Curated attack examples

| Surface | Payload | Rule(s) that fire |
|---------|---------|-------------------|
| Search  | `' UNION SELECT username, password, role, NULL FROM users--` | SIG-001, SIG-011 |
| Login   | `admin'--` (any password)                                   | SIG-011           |
| Login   | `' OR 1=1--`                                                | SIG-003, SIG-011  |
| Search  | `'; DROP TABLE products;--`                                 | SIG-002           |
| Search  | `' OR pg_sleep(5)--`                                        | SIG-007           |
| Contact | `x'); SELECT * FROM information_schema.tables;--`           | SIG-002, SIG-005  |
| Search  | `' UN/**/ION SELECT 1,2,3,4--`                              | SIG-001, SIG-004  |

The full rule library is documented inline in
[sqlshield/engines/signature.py](sqlshield/engines/signature.py).


## Tests

```bash
pip install -r requirements.txt
pip install pytest
pytest
```

The suite covers parser feature extraction, every signature rule
(positive and negative cases), the anomaly baseline lifecycle, the
aggregator's three modes, the audit JSONL round-trip, the source-tag
inference table, and the allowlist store. Tests are pure-Python and do
not require Docker or Postgres.


## Project status

See [todo_v2.md](todo_v2.md) for the full breakdown of what is
implemented and what remains. The legacy plan that predates the current
architecture is archived under
[docs/legacy/todo_v1.md](docs/legacy/todo_v1.md).
