# Expected outputs — controlled local lab

> These are **illustrative predictions**, not evidence that Docker, a deployment, or an external target was successfully assessed. Actual UUIDs, UTC timestamps, timing, hash values, and final finding counts vary.

## Setup

Run the local target fixture in a terminal on the **same host** as a Python-based RedOps Forge server:

```bash
python examples/safe_lab.py
```

Start RedOps Forge in a second terminal (from the repository root):

```bash
python -m pip install -r requirements.txt
REDOPS_DB_PATH=./data/redops.db python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8080
```

On Linux/macOS, the command above uses POSIX shell environment-variable syntax. On Windows PowerShell, set `$env:REDOPS_DB_PATH="./data/redops.db"` before running Uvicorn.

**Networking constraint:** `127.0.0.1:8001` inside a Docker container is *not* the host fixture. For reproducible tests, use the Python local mode above. The default Docker Compose profile binds the dashboard to the host loopback at port 8080 and requires a reachable, explicitly authorized target origin. Do not expose the service publicly.

## Step 1 — Health

```bash
curl -sS http://127.0.0.1:8080/api/v1/health
```

Expected fixed fields: [expected-health.json](../examples/expected-health.json).

## Step 2 — Register an approved scope

Example for a locally controlled lab; replace the expiry with a valid future UTC date:

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/scopes -H 'Content-Type: application/json' -d '{"name":"Authorized local lab","allowed_targets":["http://127.0.0.1:8001"],"approved_by":"Lab owner","authorization_ref":"ROE-LOCAL-001","valid_until":"2027-01-01T00:00:00+00:00","lab_mode":true,"max_requests":3}'
```

Illustrative response:

```json
{
  "id": "<generated-scope-id>",
  "status": "approved_scope_registered"
}
```

The service rejects expired authorizations and any target outside the exact registered origin. Replace `<generated-scope-id>` in the following request with the actual returned ID.

## Step 3 — Plan preview

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/plans -H 'Content-Type: application/json' -d '{"scope_id":"<generated-scope-id>","target":"http://127.0.0.1:8001/","skill_ids":["web-surface-review","http-security-headers","cookie-attributes"]}'
```

See [expected-plan.json](../examples/expected-plan.json). The planner is deterministic. No LLM or attack payload is executed.

## Step 4 — Safe assessment

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/runs -H 'Content-Type: application/json' -d '{"scope_id":"<generated-scope-id>","target":"http://127.0.0.1:8001/","skill_ids":["web-surface-review","http-security-headers","cookie-attributes"]}'
```

Against the supplied fixture, the initial request should return HTTP 200, record `body_downloaded=false`, and flag absent CSP, Referrer-Policy, and cookie attributes. The exact finding count may differ if the evaluator or fixture is changed.

Illustrative report: [expected-report.json](../examples/expected-report.json).

## Step 5 — Verify evidence and export JSON

```bash
curl -sS http://127.0.0.1:8080/api/v1/runs/<generated-run-id>/verify
curl -sS http://127.0.0.1:8080/api/v1/reports/<generated-run-id>
```

Expected verifier fields: `valid=true`, `checked_records>=1`, `final_hash=<runtime hash>`. If an evidence record is modified after insertion, integrity verification should return `valid=false`.

## Dashboard preview

Visit http://127.0.0.1:8080. The first load shows four KPI cards, an authorization form, an assessment form, and a runs table. After a test run, the KPI cards and recent-run table update. Selecting **View** requests the JSON report.

## Interpreting results

- **Observation**: a header or cookie attribute was absent in one response.
- **Validated finding**: needs asset/application context and owner review.
- **Not evidence of compromise**: missing browser headers do not establish exploit success.
- **Not executed**: credential attacks, exploit delivery, persistence, lateral movement, data exfiltration, stealth, or evasion.
