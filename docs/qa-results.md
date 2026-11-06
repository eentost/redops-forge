# QA Results — v0.1.0 repository sync

## Executed locally
- `pytest -q`: 14 passed.
- `python -m compileall -q backend tests`: passed.
- `node --check frontend/app.js`: passed.
- FastAPI smoke: `GET /api/v1/health` returned 200.
- Dashboard smoke: `GET /` returned 200.
- Catalog smoke: 23 categories and 12 catalog skill records returned.

## Security fixes in this sync
- URL parser errors and malformed ports are normalized to policy errors.
- Hostnames are lowercased, trailing-dot normalized, and IDNA encoded.
- IPv4/IPv6 address parsing and mixed public/private DNS answers are handled.
- DNS and authorization expiry are revalidated immediately before each HTTP request.
- Evidence chain ordering uses SQLite row insertion order, not timestamp ordering.
- API request models reject unknown fields.

## Not verified
- Docker CLI/daemon is unavailable in this execution environment; Compose build/start was NOT RUN.
- No external production target was assessed.
- DNS rebinding TOCTOU remains possible between policy resolution and the HTTP client's own connection resolution. Production requires host/firewall outbound allowlists or a pinned-resolution transport.
- No authentication/RBAC, signed RoE, PostgreSQL, external immutable evidence store, autonomous LLM planner, active exploit execution, or SIEM/EDR integration.

## Release gate
Local source/API/UI regression gate: PASS.
Container deployment gate: NOT RUN.
Production security gate: NOT READY.
