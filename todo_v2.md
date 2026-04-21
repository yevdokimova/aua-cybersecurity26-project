# Developer TODO

Status of each component and what remains to be done.

## Done

### Types (`sqlshield/types.py`)
- [x] `QueryType` IntEnum — SELECT, INSERT, UPDATE, DELETE, DDL, DCL, ADMIN, UNKNOWN
- [x] `Action` IntEnum — ALLOW (0) / BLOCK (1). Binary only, no intermediate states.
- [x] `ParsedQuery` dataclass — `raw_sql`, `normalized_sql`, `ast_fingerprint`,
  `query_type`, `tables`, `has_union`, `has_or`, `has_comment`, `has_stacked`,
  `has_subquery`, `join_depth`, `literal_count`
- [x] `EngineVerdict` dataclass — `engine`, `action`, `score`, `reasons`,
  `rule_ids`, `latency_ms`
- [x] `AuditRecord` dataclass — full schema: `id`, `timestamp`, `user`, `role`,
  `source_ip`, `source_tag`, `database`, `query_type`, `raw_sql`,
  `normalized_sql`, `ast_fingerprint`, `tables`, `final_action`,
  `engine_results`, `total_latency_ms`, `proxy_mode`

### SQL Parser (`sqlshield/parser.py`)
- [x] `Parser` class with configurable sqlglot dialect (default `"postgres"`)
- [x] Primary path: `sqlglot.parse` → AST walk to extract all 11 structural features
- [x] Regex fallback when sqlglot fails — malformed SQL is itself a signal
- [x] `_normalize()` — replaces all literals with `?` placeholders for
  canonical form used in fingerprinting
- [x] `ast_fingerprint` — SHA-256 of normalized SQL, truncated to 16 hex chars
- [x] Query-type detection via AST node type first, keyword fallback second
- [x] `has_union` — catches `exp.Union`, `exp.Intersect`, `exp.Except` at any depth
- [x] `has_stacked` — true when sqlglot parses more than one statement
- [x] `has_comment` — regex on raw SQL (`--` or `/*`)
- [x] `has_subquery` — `exp.Subquery` node found anywhere in the AST
- [x] `has_or` — `exp.Or` node found inside the `WHERE` clause specifically
- [x] `join_depth` — count of `exp.Join` nodes
- [x] `literal_count` — count of `exp.Literal` nodes
- [x] `tables` — sorted, lowercased list; handles schema-qualified names (`db.table`)


### Signature Engine (`sqlshield/engines/signature.py`)
- [x] `Condition` dataclass — 10 fields, all optional (`None` = wildcard):
  `has_union`, `has_stacked`, `has_comment`, `has_subquery`, `has_or`,
  `query_types`, `sql_contains`, `min_literals`, `min_join_depth`,
  `table_blocklist`
- [x] `Rule` dataclass — `id`, `name`, `description`, `severity`, `conditions`
- [x] Condition matching: AND within a condition, OR across conditions in a rule
- [x] Strictness levels controlling the BLOCK floor:
  - `high` — all matched rules block
  - `medium` — critical + high + medium block (default)
  - `low` — critical + high block only
- [x] Sub-floor matches still recorded in verdict for audit analysis
- [x] Bypass allowlist — fingerprints in the set skip all rule evaluation
- [x] Score = highest `SEVERITY_SCORES` among all matched rules
  (`critical=1.0`, `high=0.85`, `medium=0.6`, `low=0.3`)
- [x] Wall-clock `latency_ms` measured per inspection call
- [x] 10 built-in rules (`DEFAULT_RULES`):
  | ID      | Name                       | Severity | Key signal                                          |
  |---------|----------------------------|----------|-----------------------------------------------------|
  | SIG-001 | UNION-based injection      | critical | `has_union=True` on SELECT                         |
  | SIG-002 | Stacked queries            | critical | `has_stacked=True`                                  |
  | SIG-003 | Tautology attack           | high     | `has_or=True` + one of 5 tautology strings          |
  | SIG-004 | Comment-based obfuscation  | medium   | `has_comment=True` + `/**/` substring               |
  | SIG-005 | System table access        | high     | table in 10-entry blocklist (pg_shadow, etc.)       |
  | SIG-006 | Excessive literal injection| medium   | `min_literals=5` + `has_or=True`                   |
  | SIG-007 | Sleep/benchmark injection  | critical | substring: `sleep(`, `pg_sleep(`, `benchmark(`, `waitfor delay` |
  | SIG-008 | File operation injection   | critical | substring: `load_file(`, `into outfile`, `into dumpfile`, `copy from` |
  | SIG-009 | Boolean-based blind        | high     | `has_subquery + has_or` + `case when` substring     |
  | SIG-010 | Error-based extraction     | high     | substring: `extractvalue(`, `updatexml(`, `convert(int,` |
- [x] SIG-011 `Comment-based auth bypass` (high) — defined in `demo/app.py` and
  appended to the engine's rule list at startup (`has_comment=True` on SELECT)


### Audit Logger (`sqlshield/audit.py`)
- [x] Writes every query (ALLOW and BLOCK) to a JSONL file, one record per line
- [x] Log path from `AUDIT_LOG` env var
- [x] Thread-safe writes via `threading.Lock`
- [x] `final_action` encodes three states: `"BLOCKED"`, `"ALLOWED"`,
  `"SHIELD_OFF"` (records queries even when the shield is disabled)
- [x] `proxy_mode` field: `"enforce"` when shield is on, `"monitor"` when off
- [x] `read_all()` — reads and parses the full JSONL file


### Log Dashboard (`sqlshield/log_server.py` + `sqlshield/static/logs.html`)
- [x] Minimal stdlib HTTP server on port 8080
- [x] `GET /api/logs` — returns full audit log as JSON array
- [x] `GET /` — serves `logs.html` single-page dashboard
- [x] Dashboard features: summary counts (total / blocked / allowed / shield-off),
  filterable/searchable table, expandable row detail, auto-refresh every 3 s


### Postgre Database Connection (`demo/app.py` — `get_db`, `init_db`, `execute_query`)
- [x] psycopg2 connection via `get_db()` — reads `DB_HOST`, `DB_PORT`, `DB_NAME`,
  `DB_USER`, `DB_PASS` from environment; each call opens and closes its own
  connection (no persistent pool)
- [x] `init_db()` — retry loop (30 × 2 s) waits for PostgreSQL to be ready
  before creating schema; uses `ON CONFLICT DO NOTHING` for idempotency
- [x] Schema created on startup: `users`, `products`, `messages`, `chat_logs`
- [x] Seed data inserted on startup: 4 users (admin, alice, bob, charlie),
  5 products (Laptop, Keyboard, Mouse, Monitor, Headphones)
- [x] `execute_query(sql, fetch)` — runs raw SQL via `RealDictCursor`; commits
  on success, rolls back on error; returns `(rows, error, dropped)` tuple
- [x] Stacked-query guard in `execute_query`: parses the SQL first and short-
  circuits if `has_stacked=True` and `DROP` appears (prevents demo data loss)
- [x] `get_message_count()` — helper used by the contact route to show row counts
  after INSERT


### Demo Application (`demo/app.py` + `demo/static/`)
- [x] Stdlib HTTP server on port 8000 (no framework dependency)
- [x] 4 intentionally vulnerable query builders using string concatenation:
  `build_search`, `build_login`, `build_contact`, `build_chat`
- [x] `run_shield(sql)` — application-layer integration: parse → engine inspect
  → return `(blocked, shield_dict, parsed_query, engine_verdict)`
- [x] Routes: `/api/search`, `/api/login`, `/api/contact`, `/api/chat`,
  `/api/shield/toggle`, `/api/shield/reset`
- [x] Shield toggle — `SHIELD_ENABLED` global; every route respects it
- [x] All queries audited regardless of shield state
- [x] Log dashboard started as a daemon thread on port 8080 alongside the demo app
- [x] Frontend: `index.html` + `style.css` + `app.js` — single-page UI with
  nav bar, 4 input surfaces, SQL query display panel, shield verdict panel
- [x] 8 pre-built attack buttons on home page covering all rule categories


### Infrastructure (`docker-compose.yml`, `Dockerfile`, `demo/Dockerfile`)
- [x] Root `Dockerfile`: sqlshield-only, copies `sqlshield/` + root
  `requirements.txt`, sqlshield core deps only (`sqlglot`)
- [x] `demo/Dockerfile`: built from repo root context so it can reach
  `sqlshield/`, demo-only deps (`psycopg2-binary`)
- [x] `app` service: built from `demo/Dockerfile`, port 8000;
- [x] `dashboard` service: built from root `Dockerfile`, port 8080;
- [x] Both services mount the shared `logs` named volume at `/app/logs`
- [x] `AUDIT_LOG=/app/logs/audit.jsonl` set in both services
- [x] `db` PostgreSQL 16, port 5432, health-checked
- [x] `pgadmin` pgAdmin 4, port 5050


---

## Phase 2A — Context Enrichment

**Goal:** attach session metadata to every query before engine inspection.

**Files to create/edit:**
- `sqlshield/enricher.py` (new)
- `sqlshield/types.py` (extend `ParsedQuery`)

**Tasks:**
- [x] Add `SessionInfo` dataclass: `user`, `database`, `app_name`, `source_ip`,
  `session_id`, `params: dict`
- [x] Add `QueryContext` dataclass: `session`, `source_tag`, `role`
- [x] Extend `ParsedQuery` with an optional `context: QueryContext` field
- [x] Write `Enricher.enrich(query: ParsedQuery, session: SessionInfo) → ParsedQuery`
- [x] Implement source-tag inference from `app_name`:
  - `django / rails / sqlalchemy / prisma` → `"orm"`
  - `tableau / metabase / looker / grafana` → `"bi-tool"`
  - `langchain / openai / ai-agent / copilot` → `"ai-agent"`
  - `psql / pgadmin / dbeaver` → `"manual"`
  - Custom header `x-sqlshield-source` overrides inference
- [x] Placeholder role inference: `role = session.user` (real lookup deferred)
- [x] Write unit tests covering each source-tag branch + unknown → `"unknown"`

---

## Phase 2B — Anomaly Detection Engine

**Goal:** learn per-user behavioral baselines; flag deviations after a learning period.
Based on Kamra et al. (VLDB Journal 2008).

**Files to create/edit:**
- `sqlshield/engines/anomaly.py` (new)
- `sqlshield/engines/__init__.py` (register `AnomalyEngine`)

---

### Approach options

There are three viable approaches, from simplest to most powerful.
The project implements **Option A** first; Option B or C can replace the
scoring step later without changing the engine interface.

#### Option A — Statistical baseline (implement this first)

Per-user feature counters + z-score outlier detection. No training data,
no extra dependencies. This is what Kamra et al. describe.

How it works:
- During the learning period, record counts/distributions for each user
- After learning, for each incoming query compute a deviation score per
  dimension using z-score: `z = (x - mean) / std`
- A z-score > 3 on any dimension is flagged as anomalous (3σ rule)
- Aggregate flagged dimensions into a final 0.0–1.0 score

Pros: zero extra dependencies, interpretable, fast, works with very few queries
Cons: assumes roughly normal distributions; won't catch slow-drift attacks

#### Option B — Autoencoder (upgrade path)

Train a small neural network on the feature vectors of normal queries.
At inference time, flag queries with high reconstruction error.

Architecture (scikit-learn `MLPRegressor` is enough, or PyTorch for more control):
```
Input: 8-dim feature vector per query
  [join_depth, literal_count, has_union, has_or, has_subquery,
   has_comment, has_stacked, query_type_onehot_bucket]

Encoder:  8 → 6 → 4  (ReLU activations)
Decoder:  4 → 6 → 8  (ReLU, linear output)

Loss: MSE(input, reconstruction)
Anomaly score: reconstruction_error / max_seen_error  (normalized to 0–1)
```

Training: fit on the queries collected during the learning period.
Threshold: flag queries where `reconstruction_error > mean_train_error + 2σ`.

Dependencies to add to `requirements.txt`:
```
scikit-learn>=1.4    # MLPRegressor autoencoder — no GPU needed
```

Or for a full PyTorch version (overkill for this project but mentioned for completeness):
```
torch>=2.2
```

Pros: learns non-linear patterns, handles feature correlations
Cons: needs enough learning data (~500+ queries) to train meaningfully;
      less interpretable than Option A

#### Option C — LSTM session model (most powerful, most complex)

Model the sequence of query fingerprints within a user session as a
language model. Flag when the next query has low predicted probability.

Architecture:
```
Input:  sequence of query feature vectors (variable length, per session)
LSTM:   hidden_size=64, num_layers=2
Output: probability distribution over seen fingerprints (softmax)

Anomaly score: -log P(current query | previous queries in session)
```

Dependencies:
```
torch>=2.2
```

Pros: captures temporal ordering and session context; detects
      multi-step attacks that individually look normal
Cons: needs session boundary tracking; requires far more data to train;
      cold-start problem for new users; much harder to debug

---

### Feature vector (used by all three options)

Extract these 8 numeric features from each `ParsedQuery`:

| Feature | Source | Notes |
|---|---|---|
| `join_depth` | `ParsedQuery.join_depth` | raw int |
| `literal_count` | `ParsedQuery.literal_count` | raw int |
| `has_union` | `ParsedQuery.has_union` | 0 / 1 |
| `has_or` | `ParsedQuery.has_or` | 0 / 1 |
| `has_subquery` | `ParsedQuery.has_subquery` | 0 / 1 |
| `has_comment` | `ParsedQuery.has_comment` | 0 / 1 |
| `has_stacked` | `ParsedQuery.has_stacked` | 0 / 1 |
| `query_type` | `ParsedQuery.query_type` | int enum value |

---

### Implementation tasks (Option A — statistical baseline)

- [x] Define `Baseline` dataclass per `(user, role)`:
  - `seen_fingerprints: dict[str, int]`
  - `seen_tables: dict[str, int]`
  - `query_type_dist: dict[str, int]` (SELECT / INSERT / UPDATE / DELETE / DDL)
  - `active_hours: list[int]` (24 ints, query count per hour)
  - `literal_stats: (mean, std)`, `join_stats: (mean, std)`
  - `total_queries: int`, `first_seen: datetime`, `last_seen: datetime`
  - `learning: bool`
- [x] Implement `AnomalyEngine(BaseEngine)` (default 100 queries learning,
  always-allow during learning, z-score scoring after)
- [x] Implement 5 scoring dimensions:
  1. Novel fingerprint — AST shape never seen from this user (score 1.0)
  2. Novel table — user never accessed this table (score 0.8)
  3. First mutation — user was read-only, now doing INSERT/UPDATE/DELETE/DDL (score 0.9)
  4. Complexity spike — `z_score(literal_count) > 3` or `z_score(join_depth) > 3` (score proportional to z)
  5. Temporal anomaly — query hour has zero count in `active_hours` (score 0.6)
- [x] Weighted aggregation: `final_score = max(dimension_scores)`
- [x] Threshold: `final_score >= 0.7` → BLOCK
- [x] Persist baselines to JSON file (`baselines.json` next to audit log)
- [x] Expose `reset_baseline(user)` and `export_baselines()` methods
- [x] Write tests: learning phase always allows, post-learning flags each anomaly dimension

---

## Phase 2C — LLM Policy Engine

**Goal:** constrain AI-generated queries; defend against prompt-to-SQL injection
(Pedro et al., ICSE 2025).

**Files to create/edit:**
- `sqlshield/engines/llm_policy.py` (new)
- `sqlshield/engines/__init__.py` (register `LLMPolicyEngine`)
- `sqlshield.yaml` (add `llm_policy` config section)

**Tasks:**
- [ ] Implement `LLMPolicyEngine(BaseEngine)`:
  - Activates **only** when `source_tag == "ai-agent"`; all other queries
    return `ALLOW` with score 0 immediately
- [ ] Implement 7 policy rules:
  - `LLM-001` Schema scope — query touches a table not in `allowed_tables`
  - `LLM-002` Mutation blocking — INSERT / UPDATE / DELETE / DDL from AI
  - `LLM-003` Row limit — no `LIMIT` clause, or `LIMIT > max_row_limit`
  - `LLM-004` WHERE required — sensitive tables queried without WHERE
  - `LLM-005` Join depth limit — `join_depth > max_join_depth`
  - `LLM-006` Subquery restriction — `has_subquery` when `block_subqueries=true`
  - `LLM-007` UNION restriction — `has_union` (strong prompt-injection signal)
- [ ] Add config fields to `sqlshield.yaml`:
  ```yaml
  llm_policy:
    allowed_tables: [products, orders]
    block_mutations: true
    max_row_limit: 100
    require_where_on: [customers, users]
    max_join_depth: 2
    block_subqueries: false
  ```
- [ ] Write tests: non-AI queries pass through, each LLM rule fires correctly

---

## Phase 2D — Verdict Aggregator

**Goal:** run all three engines in parallel and merge into one decision.

**Files to create/edit:**
- `sqlshield/verdict.py` (new)
- `sqlshield/pipeline.py` (wire aggregator in)

**Tasks:**
- [x] Implement `Aggregator.evaluate(query: ParsedQuery) → FinalVerdict`
  - Run engines via `ThreadPoolExecutor` (parallel)
  - Wrap each engine in `try/except` so one broken engine can't crash the pipeline
  - ANY engine BLOCK → final BLOCK; otherwise ALLOW
- [x] Add `FinalVerdict` dataclass: `action`, `engine_verdicts`, `aggregate_score`,
  `latency_ms`
- [x] Implement three operating modes (from config):
  - `enforce` — respect engine verdicts
  - `monitor` — always ALLOW but log what would have blocked
  - `learning` — always ALLOW (anomaly baseline building)
- [x] Wire the aggregator into `demo/app.py` (no separate `pipeline.py`; the demo
  is the only consumer in this scope)
- [x] Update audit log to record one entry per engine verdict
- [x] Write tests for each mode and for engine-failure isolation

---

## Phase 2E — Wire-Protocol Proxy

**Goal:** intercept queries at the network layer so any application can use SQL Shield
by changing only its connection string (`port 5432` → `port 6432`).

**Files to create:**
- `sqlshield/protocol/__init__.py`
- `sqlshield/protocol/postgres.py`
- `sqlshield/admin/__init__.py`
- `sqlshield/admin/server.py`
- `sqlshield/__main__.py`
- `sqlshield.yaml` (add proxy config section)

**Tasks:**
- [ ] Implement `PostgresProxy` as an `asyncio` TCP server on port 6432
- [ ] Handle PostgreSQL wire protocol v3 startup:
  - Parse 4-byte length + 4-byte protocol version + null-terminated key=value pairs
  - Extract `user`, `database`, `application_name` → build `SessionInfo`
  - Forward startup to real backend (port 5432), relay auth exchange
  - Wait for `ReadyForQuery` (`Z` / `0x5A`) before entering query loop
- [ ] Implement query interception loop:
  - Simple Query (`Q` / `0x51`): extract null-terminated SQL string
  - Extended Query Parse (`P` / `0x50`): skip statement name, read query string
  - For each query:
    - Call `pipeline.inspect(sql, session)`
    - BLOCK → send `ErrorResponse` (`E`, severity `S`, code `42501`,
      message `"SQL Shield: query blocked"`) + `ReadyForQuery('I')`
    - ALLOW → forward to backend, relay response until next `ReadyForQuery`
  - Terminate (`X` / `0x58`): forward, close both connections
  - All other messages: passthrough (Bind, Execute, Describe, Sync, etc.)
- [ ] Add `sqlshield.yaml` proxy section:
  ```yaml
  proxy:
    listen_port: 6432
    backend_host: localhost
    backend_port: 5432
  ```
- [ ] Implement admin HTTP API (`aiohttp`, port 9090):
  - `GET /health`
  - `GET /api/v1/stats` — total queries, blocked, allowed, latency percentiles
  - `GET /api/v1/baselines` — export anomaly baselines
  - `POST /api/v1/baselines/reset` — reset a user's baseline
- [ ] Implement `sqlshield/__main__.py` CLI entry point:
  - `python -m sqlshield` starts proxy + admin API
- [ ] Update `docker-compose.yml`:
  - Replace direct psycopg2 demo connection with proxy connection on port 6432
  - Remove `run_shield()` call from `demo/app.py`
  - Add proxy service, expose ports 6432 and 9090
- [ ] Write integration tests: connect a real psycopg2 client to the proxy,
  verify injections are blocked and normal queries pass through

---

## Phase 2F — Allowlist Admin Interface

**Goal:** let an operator mark a blocked query as a false positive so it is
never blocked again. Builds on the existing `bypass_fingerprints` set in
`SignatureEngine` — that mechanism already skips all rule evaluation for
known fingerprints; this phase just makes it manageable at runtime.

**Files to create/edit:**
- `sqlshield/allowlist.py` (new) — persistent allowlist store
- `sqlshield/log_server.py` (extend) — add allowlist API endpoints
- `sqlshield/static/logs.html` (extend) — "Allow" button on blocked rows,
  allowlist management tab

---

### How the existing bypass works (context)

`SignatureEngine` already has a bypass fast-path:
```python
if query.ast_fingerprint in self.bypass:
    return EngineVerdict(action=ALLOW, score=0.0, ...)
```
`self.bypass` is a `set[str]` passed in at construction time. Currently it
is always empty. This phase makes it a live, persisted, API-managed set.

---

### Allowlist store (`sqlshield/allowlist.py`)

- [x] `AllowlistEntry` dataclass:
  - `fingerprint: str` — 16-char SHA-256 prefix (matches `ast_fingerprint`)
  - `raw_sql_example: str` — one representative query that produced this fingerprint
  - `normalized_sql: str` — the canonical form (easier to read than the fingerprint)
  - `added_at: float` — Unix timestamp
  - `added_by: str` — operator identifier (free text, e.g. `"admin"`)
  - `reason: str` — free-text note explaining why this is a false positive
- [x] `AllowlistStore` class:
  - Persists to `allowlist.json` next to `audit.jsonl` (path from `ALLOWLIST`
    env var, same default directory as `AUDIT_LOG`)
  - `add(entry: AllowlistEntry) → None` — append and flush to disk
  - `remove(fingerprint: str) → bool` — delete entry, return False if not found
  - `contains(fingerprint: str) → bool` — O(1) lookup via in-memory set
  - `list_all() → list[AllowlistEntry]` — return all entries sorted by `added_at`
  - Thread-safe reads/writes via `threading.Lock`
  - Loads from disk on startup
- [x] Wire `AllowlistStore` into `SignatureEngine` via `bypass_fingerprints=store`
  (engine re-checks on every query so additions take effect immediately,
  no restart needed)

### Admin API endpoints (extend `sqlshield/log_server.py`)

- [x] `GET /api/allowlist` — return all entries as JSON array
- [x] `POST /api/allowlist` — add an entry; body:
  ```json
  { "fingerprint": "abc123...", "raw_sql_example": "...",
    "normalized_sql": "...", "added_by": "admin", "reason": "false positive on OR in WHERE" }
  ```
  Returns `201` with the created entry, or `409` if fingerprint already exists
- [x] `DELETE /api/allowlist/<fingerprint>` — remove entry; returns `204` or `404`
- [x] `GET /api/allowlist/<fingerprint>` — get one entry by fingerprint

### Dashboard UI (extend `sqlshield/static/logs.html`)

- [x] Add **"Allow"** button on every BLOCKED row in the audit table; modal
  prefilled with the fingerprint, raw SQL, and normalized SQL.
- [x] Add **Allowlist tab** alongside the audit log table with a per-row
  **Remove** button.
- [x] Show an `allowlisted` badge in the audit log for queries whose
  fingerprint is currently in the allowlist.

### Behaviour after allowlisting

```
query arrives → fingerprint in allowlist?
                    yes → ALLOW immediately (score 0.0, no rules evaluated)
                          audit record: final_action="ALLOWED", rule_ids=[], 
                                        proxy_mode="allowlisted"
                    no  → normal engine pipeline
```

- [x] The signature engine reports `rule_ids=["ALLOWLIST"]` so the dashboard
  can spot allowlisted queries without a schema change
- [x] Add an **Allowlisted** summary stat card to the dashboard header


## Out of scope for the course project

Phase 2C (LLM policy engine) and Phase 2E (Postgres wire-protocol proxy + admin
API) were intentionally deferred. They are well-defined and can be added later
without changing the existing engine or aggregator interfaces, but they were
too large to land cleanly within the course timeline.
