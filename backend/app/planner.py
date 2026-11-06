from urllib.parse import urlparse
from .catalog import SKILLS


def build_plan(target: str, skill_ids: list[str], max_requests: int) -> dict:
    by_id = {skill["id"]: skill for skill in SKILLS}
    selected = [by_id[item] for item in skill_ids]
    steps = []
    if "web-surface-review" in skill_ids:
        steps.append({"order": 1, "skill_id": "web-surface-review", "action": "Request the approved origin and capture response metadata", "expected_evidence": ["status_code", "http_version", "response_headers", "content_length"]})
    if "http-security-headers" in skill_ids:
        steps.append({"order": len(steps) + 1, "skill_id": "http-security-headers", "action": "Evaluate selected browser security response headers", "expected_evidence": ["missing_header_observations"]})
    if "cookie-attributes" in skill_ids:
        steps.append({"order": len(steps) + 1, "skill_id": "cookie-attributes", "action": "Inspect cookie flags without retaining cookie values", "expected_evidence": ["cookie_attribute_observations"]})
    return {
        "planner": "deterministic-policy-planner",
        "planner_mode": "rules-based-mvp",
        "target_origin": urlparse(target)._replace(path="", params="", query="", fragment="").geturl(),
        "selected_skills": [{"id": item["id"], "name": item["name"], "risk": item["risk"]} for item in selected],
        "execution_profile": "safe-http-review",
        "max_requests": min(int(max_requests), 5),
        "steps": steps,
        "blocked_capabilities": ["credential_attacks", "exploit_delivery", "persistence", "lateral_movement", "data_exfiltration", "stealth_or_evasion"],
        "approval_required": True
    }
