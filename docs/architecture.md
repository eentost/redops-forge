# RedOps Forge Architecture v0.1.0

## Runtime boundaries
- FastAPI serves the API and static dashboard.
- SQLite stores scopes, runs, findings, evidence, and audit events.
- The planner is deterministic; no model invocation occurs in v0.1.0.
- The runner performs bounded HTTP metadata review only.

## Trust boundaries
1. Operator submits an authorization scope.
2. Policy validates expiry, exact origin, and address class.
3. Planner previews only enabled passive skills.
4. Runner executes bounded GET requests with redirects constrained to the approved origin.
5. Evidence records are SHA-256 chained and can be revalidated.

## Explicitly out of scope
Exploit delivery, credential attacks, persistence, lateral movement, exfiltration, stealth, and evasion are not implemented.

## Production hardening backlog
Authentication/RBAC, PostgreSQL, outbound firewall allowlists, DNS pinning/rebinding defenses, immutable evidence storage, signed attestations, and independent verifier.
