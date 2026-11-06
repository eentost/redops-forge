import asyncio
import json
import uuid
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from urllib.parse import urljoin, urlsplit
import httpx

from .store import add_evidence, connect, now_iso
from .policy import validate_target

SAFE_RESPONSE_HEADERS = {
    "content-type", "content-length", "date", "server", "cache-control",
    "strict-transport-security", "content-security-policy", "x-content-type-options",
    "referrer-policy", "x-frame-options", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-resource-policy"
}
SECURITY_HEADERS = {
    "strict-transport-security": ("HSTS", "medium", "HTTPS response does not include Strict-Transport-Security."),
    "content-security-policy": ("Content Security Policy", "medium", "Response does not include Content-Security-Policy."),
    "x-content-type-options": ("MIME Sniffing Protection", "low", "Response does not include X-Content-Type-Options."),
    "referrer-policy": ("Referrer Policy", "low", "Response does not include Referrer-Policy.")
}


def add_finding(run_id: str, code: str, severity: str, title: str, description: str, evidence: dict) -> None:
    with connect() as db:
        db.execute("INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                   (str(uuid.uuid4()), run_id, code, severity, title, description,
                    json.dumps(evidence, sort_keys=True), now_iso()))


def inspect_headers(run_id: str, headers: httpx.Headers, scheme: str, check_headers: bool, check_cookies: bool) -> list[dict]:
    findings = []
    lower = {k.lower(): v for k, v in headers.items()}
    if check_headers:
        for header, (code, severity, description) in SECURITY_HEADERS.items():
            if header == "strict-transport-security" and scheme != "https":
                continue
            if header not in lower:
                item = {"code": code, "severity": severity, "title": f"Missing {header}", "description": description}
                add_finding(run_id, code, severity, item["title"], description, {"missing_header": header})
                findings.append(item)
    set_cookie = headers.get_list("set-cookie") if check_cookies else []
    for index, raw in enumerate(set_cookie):
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:
            continue
        for name, morsel in cookie.items():
            missing = []
            if scheme == "https" and not morsel["secure"]:
                missing.append("Secure")
            if not morsel["httponly"]:
                missing.append("HttpOnly")
            if not morsel["samesite"]:
                missing.append("SameSite")
            if missing:
                item = {"code":"COOKIE_ATTRIBUTES", "severity":"low", "title":"Cookie attributes need review",
                        "description":"A cookie is missing one or more recommended security attributes.",
                        "cookie_index": index, "cookie_name": name, "missing": missing}
                add_finding(run_id, "COOKIE_ATTRIBUTES", "low", item["title"], item["description"], item)
                findings.append(item)
    return findings


async def run_safe_http_review(run_id: str, target: str, max_requests: int, skill_ids: list[str],
                               allowed_targets: list[str], valid_until: str, lab_mode: bool) -> dict:
    started = datetime.now(timezone.utc)
    current = target
    request_count = 0
    responses = []
    findings = []
    timeout = httpx.Timeout(6.0, connect=3.0)
    async with httpx.AsyncClient(timeout=timeout, verify=True, follow_redirects=False, trust_env=False,
                                 headers={"User-Agent": "RedOpsForge-SafeAssessment/0.1",
                                          "Accept": "text/html,application/json;q=0.9,*/*;q=0.1"}) as client:
        for _ in range(min(max_requests, 5)):
            # Re-check authorization and DNS policy before each outbound request.
            # Host-level egress filtering remains necessary to close DNS-rebinding TOCTOU.
            validate_target(current, allowed_targets, valid_until, lab_mode)
            request_count += 1
            started_request = datetime.now(timezone.utc)
            async with client.stream("GET", current) as response:
                safe_headers = {k: v for k, v in response.headers.items() if k.lower() in SAFE_RESPONSE_HEADERS}
                response_meta = {"origin": _origin(current), "path": urlsplit(current).path or "/",
                                 "status_code": response.status_code, "http_version": response.http_version,
                                 "headers": safe_headers, "content_length": response.headers.get("content-length", "unknown"),
                                 "body_downloaded": False,
                                 "elapsed_ms": round((datetime.now(timezone.utc) - started_request).total_seconds() * 1000, 2)}
                status_code = response.status_code
                location = response.headers.get("location")
                findings.extend(inspect_headers(run_id, response.headers, urlsplit(current).scheme,
                                                "http-security-headers" in skill_ids,
                                                "cookie-attributes" in skill_ids))
            responses.append(response_meta)
            add_evidence(run_id, "http_response_metadata", response_meta)
            if status_code not in {301, 302, 303, 307, 308} or not location:
                break
            next_url = urljoin(current, location)
            parsed_next = urlsplit(next_url)
            if parsed_next.query or parsed_next.fragment or parsed_next.username or parsed_next.password:
                add_evidence(run_id, "redirect_blocked", {"from_origin": _origin(current),
                                                          "reason": "redirect contains query, fragment or URL credentials"})
                break
            if _origin(next_url) != _origin(target):
                add_evidence(run_id, "redirect_blocked", {"from_origin": _origin(current),
                                                          "to_origin": _origin(next_url), "reason": "cross-origin redirect"})
                break
            try:
                validate_target(next_url, allowed_targets, valid_until, lab_mode)
            except ValueError as exc:
                add_evidence(run_id, "redirect_blocked", {"from_origin": _origin(current), "reason": str(exc)})
                break
            current = next_url
            await asyncio.sleep(1.0)
    elapsed = round((datetime.now(timezone.utc) - started).total_seconds(), 3)
    summary = {"request_count": request_count, "response_count": len(responses),
               "finding_count": len(findings), "duration_seconds": elapsed,
               "status": "completed", "execution_profile": "safe-http-review"}
    return {"summary": summary, "responses": responses, "findings": findings}


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    return (parsed.scheme, (parsed.hostname or "").lower(), parsed.port or (443 if parsed.scheme == "https" else 80))
