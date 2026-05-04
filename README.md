# SQLShield

A PostgreSQL wire-protocol proxy that intercepts and inspects every SQL query before it reaches the database. Paired with an intentionally vulnerable demo application. Built for the AUA Cybersecurity 2026 course project.

---

## Architecture

```
Browser / Demo App (port 8000)
        |
        | PostgreSQL wire protocol
        v
  ┌──────────────────────────────────────────────┐
  │              SQLShield Proxy (port 6432)     │
  │                                              │
  │  Parser → Enricher → Aggregator              │
  │                          │                   │
  │          ┌───────────────┼───────────────┐   │
  │          ▼               ▼               ▼   │
  │   SignatureEngine  AnomalyEngine  LLMPolicy  │
  │   (11 rules)       (per-user)     Engine     │
  │                                              │
  │  enforce: block  │  monitor: log only        │
  └──────────────────┼───────────────────────────┘
                     │ allowed queries only
                     ▼
             PostgreSQL (port 5432)
                     │
              Audit log (JSONL)
                     │
                     ▼
          Dashboard (port 8080)
```

All traffic, including AI-generated SQL from the chatbot, flows through the proxy. The demo app never connects to Postgres directly.

---

## Project structure

```
aua-cybersecurity26-project/
├── sqlshield/                  # The proxy library
│   ├── parser.py               # sqlglot AST parser, 11 structural features
│   ├── enricher.py             # Attaches session context, infers source_tag
│   ├── pipeline.py             # Wires engines together, reads sqlshield.yaml
│   ├── verdict.py              # Aggregates engine verdicts (enforce/monitor)
│   ├── allowlist.py            # Persistent fingerprint allowlist
│   ├── audit.py                # JSONL audit logger
│   ├── log_server.py           # Audit dashboard HTTP server
│   ├── engines/
│   │   ├── signature.py        # Rule-based engine (11 default rules)
│   │   ├── anomaly.py          # Statistical per-user baseline engine
│   │   └── llm_policy.py       # Structural policy engine for AI-generated SQL
│   ├── protocol/
│   │   └── postgres.py         # PostgreSQL wire protocol handler
│   └── admin/
│       └── server.py           # Admin HTTP API (shield toggle, reset)
├── demo/                       # Vulnerable demo application
│   ├── app.py                  # HTTP server (search / login / contact / chat)
│   ├── llm.py                  # Ollama client, SQL generation, intent routing
│   ├── static/                 # Frontend (HTML, CSS, JS)
│   └── Dockerfile
├── sqlshield.yaml              # Proxy configuration
├── docker-compose.yml
├── Dockerfile                  # Proxy image
└── requirements.txt
```

---

## How SQLShield works

Every query that arrives at the proxy goes through three steps:

**1. Parse**: `sqlglot` builds an AST and extracts 11 features: query type, table names, join depth, literal count, presence of UNION / subquery / stacked statements / comments / OR conditions, and a normalized AST fingerprint.

**2. Enrich**: the enricher attaches the client's session (user, role, application name) and infers a `source_tag`. Connections whose `application_name` starts with `ai-agent/` are tagged accordingly, which activates the LLM Policy Engine.

**3. Inspect**: three engines run in parallel and each returns a score (0–1) and a verdict:

| Engine | What it checks |
|--------|---------------|
| **SignatureEngine** | Matches 11 rule patterns: UNION injection, stacked queries, tautologies, comment obfuscation, system table access, sleep/benchmark, file ops, error-based extraction, auth bypass, and more. Strictness (`high / medium / low`) controls which severity levels block. |
| **AnomalyEngine** | Builds a per-user behavioral baseline during a configurable learning period (default 100 queries), then flags novel fingerprints, new tables, first write from a read-only user, statistical complexity spikes (z-score), and queries at unusual hours. Trains a small autoencoder (scikit-learn) on the baseline feature vectors. |
| **LLMPolicyEngine** | Active only for `source_tag = "ai-agent"`. Enforces structural rules on AI-generated SQL: allowed tables, no mutations, LIMIT required, WHERE required on sensitive tables, join depth cap, and UNION prohibition. Zero cost for non-AI traffic. |

The **Aggregator** takes the worst verdict across all engines. In `enforce` mode the query is rejected; in `monitor` mode it is logged but allowed through. Every decision is written to the JSONL audit log.

---

## How the demo app works

The demo is an intentionally vulnerable store application with four attack surfaces:

| Surface | Vulnerability | Classic injection example |
|---------|--------------|--------------------------|
| **Search** | Unsanitized `LIKE` query | `' AND (SELECT 'x' FROM users WHERE username='admin')='x' --` |
| **Login** | String-concatenated auth query | `admin' --` |
| **Contact** | Unsanitized `INSERT` | `x'); DROP TABLE messages; --` |
| **AI Chat** | Prompt injection -> policy-violating SQL | `List all users in the system.` |

**Classic injection flow:** User input is concatenated directly into SQL -> query goes to the proxy -> SQLShield inspects it -> blocked (shield ON) or executed (shield OFF).

**AI chat flow:** User message -> intent classifier -> if data query, Ollama (`llama3.2:3b`) generates SQL -> SQL sent to proxy with `application_name=ai-agent/llama3.2:3b` -> LLMPolicyEngine activates -> blocked if policy violated, otherwise results returned and formatted.

The shield toggle in the navigation bar switches the proxy between `enforce` and `monitor` mode via the admin API. The audit dashboard at port 8080 shows every query, its score, which rules fired, and lets operators allowlist fingerprints.

---

## Prerequisites

- **Docker** and **Docker Compose** (v2)
- **Ollama** installed on the host with `llama3.2:3b` pulled

Install Ollama from [ollama.com](https://ollama.com), open the app to start the server, then pull the model:

```bash
ollama pull llama3.2:3b
```

The Docker setup mounts `~/.ollama` into the container, so the model is not re-downloaded on each run.

---

## Running the project

```bash
docker compose up --build
```

Wait for all services to report healthy (the `llm` service healthcheck confirms the model is loaded). Then open:

| URL | Service |
|-----|---------|
| http://localhost:8000 | Demo application |
| http://localhost:8080 | Audit log dashboard |
| http://localhost:5050 | pgAdmin (admin@demo.com / admin) |

The proxy listens on port `6432`. The demo app connects through it automatically, you do not need to interact with it directly.

On first start the app creates the schema and seeds the database (4 users, 5 products).

**Shield starts OFF:** Run an attack example to see it succeed, then toggle the shield ON and repeat to see it blocked. The dashboard records every attempt with the rule IDs and score.
