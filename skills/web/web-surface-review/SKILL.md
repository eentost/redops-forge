# Web Surface Review
Status: active · Mode: passive · Risk: low

## Purpose
Collect limited response metadata from an explicitly authorized HTTP(S) origin.

## Preconditions
- Exact origin is registered in an unexpired scope.
- DNS policy passes and private destinations are allowed only in lab mode.
- Operator has confirmed the Rules of Engagement.

## Procedure
1. Send a bounded HTTP GET to the selected URL.
2. Do not download the response body.
3. Record status, protocol, allowlisted headers, content length, path and elapsed time.
4. Follow same-origin redirects only, revalidating scope and DNS before each request.
5. Stop on cross-origin redirects, URL credentials, query strings, fragments or policy errors.

## Evidence
Response metadata and policy-block events, hash chained. Never store body content or authorization secrets.

## Limitations
DNS rebinding TOCTOU is not fully prevented without host-level egress controls.
