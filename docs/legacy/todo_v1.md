# Developer TODO

Status of each component and what remains to be done.

## Done

- [x] **Web application** (`app.py`) -- HTTP server with search, login,
  contact form, and chatbot endpoints
- [x] **Frontend** (`static/`) -- single-page UI with nav bar, four
  input surfaces, SQL query display panel, Shield verdict panel
- [x] **Shield toggle** -- UI switch that enables/disables protection
  at runtime via `/api/shield/toggle`
- [x] **Database layer** (`db.py`) -- PostgreSQL-style interface
  (`connect`, `execute`, `fetchall`, `close`) with schema, seed data,
  and in-memory simulation
- [x] **Shield Stage 1: Syntax Check** -- pattern matching for SQL
  keywords, dangerous characters, and known injection patterns
- [x] **Shield Stage 2: Behavior Check** -- per-IP rate limiting and
  repeat-offender tracking
- [x] **Shield Stage 3: AI Check** -- heuristic scoring (special-char
  ratio, unbalanced quotes, keyword density, structural anomalies)
- [x] **Vulnerable query builders** (`do_search`, `do_login`,
  `do_insert_message`, `do_insert_chat_log`) -- string concatenation
  on purpose to demonstrate injections
- [x] **README** with project structure and demo walkthrough

## To Do

### 1. Connect to a real PostgreSQL database

**Where:** `db.py`, class `Database`

The interface is already correct. Every method has a `# REAL DB:` 
comment showing the psycopg2 replacement. Steps:

1. Install psycopg2: `pip install psycopg2-binary`
2. Update `DB_CONFIG` at the top of `db.py` with real credentials
3. In `connect()`, uncomment:
   ```python
   self.conn = psycopg2.connect(**DB_CONFIG)
   self.cursor = self.conn.cursor()
   ```
4. In `execute()`, uncomment:
   ```python
   self.cursor.execute(query)
   self.conn.commit()
   ```
5. In `fetchall()`, uncomment:
   ```python
   return self.cursor.fetchall()
   ```
6. In `fetchone()`, uncomment:
   ```python
   return self.cursor.fetchone()
   ```
7. In `close()`, uncomment:
   ```python
   self.cursor.close()
   self.conn.close()
   ```
8. Run the `SCHEMA` SQL to create the tables, then insert `SEED_USERS`
   and `SEED_PRODUCTS`
9. Remove the `_simulate_select`, `_simulate_insert` methods and all
   helper functions below them (`_looks_like_injection_in_query`,
   `_extract_like_value`, `_extract_login_values`,
   `_extract_insert_values`) -- they are only needed for the simulation

### 2. Fix the vulnerable queries (after demo)

**Where:** `app.py`, functions `do_search`, `do_login`,
`do_insert_message`, `do_insert_chat_log`

Every query builder currently uses string concatenation:
```python
query = "SELECT * FROM users WHERE username='" + username + "'"
```

Replace with parameterized queries:
```python
db.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
```

This makes SQL injection impossible at the database level, regardless
of Shield. The `db.py` comment labeled `# SAFE:` shows the pattern.

### 3. Improve Shield Stage 1 (Syntax Check)

**Where:** `shield.py`, function `syntax_check`

Current implementation uses flat lists of keywords and patterns.
Possible improvements:

- Use word-boundary matching so "drop shipping" is not flagged
  (currently it triggers on the word DROP)
- Add support for URL-encoded and hex-encoded payloads
  (`%27` = single quote, `0x27`, etc.)
- Add support for case-mixing evasion (`SeLeCt`, `uNiOn`)

### 4. Improve Shield Stage 2 (Behavior Check)

**Where:** `shield.py`, function `behavior_check`

Current implementation uses in-memory dicts that reset when the
server restarts. Possible improvements:

- Persist request history to the database or Redis
- Add session tracking (not just IP-based)
- Track which specific inputs were rejected, not just the count
- Add configurable thresholds (currently hardcoded at 15/30 per minute)

### 5. Replace Shield Stage 3 with a real ML model

**Where:** `shield.py`, function `ai_check`

Current implementation uses a hand-crafted scoring heuristic.
To replace it with an actual model:

1. Collect a labeled dataset of normal inputs and injection attempts
2. Train a classifier (e.g. scikit-learn, a small neural network)
3. Save the model to a file (e.g. `model.pkl`)
4. In `ai_check`, load the model and call `model.predict(text)`
5. Map the model output to accepted/suspicious/rejected verdicts

The function signature stays the same -- it takes a string and
returns a dict with `verdict`, `stage`, and `detail`.

### 6. Switch from stdlib HTTP server to Flask/FastAPI

**Where:** `app.py`

The current server uses `http.server` from the standard library
(zero dependencies). For production or more features, migrate to
Flask or FastAPI:

- Replace `DemoHandler` with Flask route decorators
- Move `_send_json` to Flask's `jsonify`
- Add proper error handling and logging
- Add HTTPS support

### 7. Add tests

**Where:** new file `tests.py` or `tests/` directory

Priority test cases:

- Each injection example from the README is blocked when Shield is ON
- Each injection example succeeds when Shield is OFF
- Normal inputs (e.g. "Laptop", valid credentials) are accepted
  regardless of Shield state
- Behavior check escalates after repeated rejections
- AI check scores known-safe inputs below threshold
