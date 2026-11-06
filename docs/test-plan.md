# Test Plan

## Unit
- URL origin normalization and exact-scope enforcement.
- Authorization expiry and timezone validation.
- Private, loopback, link-local, reserved, and multicast address policy.
- Evidence-chain tamper detection.

## Integration
- Health and catalog endpoints.
- Scope registration and expiry rejection.
- Plan preview and unsupported-skill rejection.
- Local HTTP fixture assessment and evidence retrieval.

## Negative and regression
- Cross-origin redirects must stop.
- URL credentials, query strings, and fragments must be rejected.
- Private targets must require explicit lab mode.
- No response body or cookie value may be persisted.

## Release gate
Do not claim deployment readiness until Docker Compose build/start, API integration, negative tests, and host egress controls have been verified.
