CATEGORIES = [
    ("web", "Web Application"), ("wireless", "Wireless"),
    ("infrastructure", "Infrastructure & Red Team"), ("exploit", "Exploit Development"),
    ("fuzzing", "Fuzzing & Vulnerability Research"), ("post_exploitation", "Post-Exploitation"),
    ("identity", "Auth & Identity"), ("recon", "Reconnaissance"),
    ("api", "API Security"), ("container", "Container & Kubernetes"),
    ("cicd", "CI/CD & Pipeline"), ("crypto", "Cryptography"),
    ("privesc", "Privilege Escalation"), ("forensics", "Forensics & C2"),
    ("supply_chain", "Supply Chain"), ("social", "Social Engineering"),
    ("utility", "Utility"), ("ad", "Active Directory"), ("cloud", "Cloud"),
    ("mobile", "Mobile"), ("iot", "IoT & Embedded"), ("network", "Network Attacks"),
    ("ai", "AI Security")
]

SKILLS = [
    {"id":"web-surface-review", "name":"Web Surface Review", "category":"web", "status":"active", "mode":"passive", "risk":"low", "description":"Review the explicitly scoped web origin and record response metadata."},
    {"id":"http-security-headers", "name":"HTTP Security Headers", "category":"web", "status":"active", "mode":"passive", "risk":"low", "description":"Evaluate common browser security response headers."},
    {"id":"cookie-attributes", "name":"Cookie Attribute Review", "category":"web", "status":"active", "mode":"passive", "risk":"low", "description":"Inspect Set-Cookie attributes without storing cookie values."},
    {"id":"tls-posture", "name":"TLS Posture Review", "category":"crypto", "status":"planned", "mode":"passive", "risk":"low", "description":"TLS certificate and protocol posture checks; adapter not enabled in MVP."},
    {"id":"api-contract-review", "name":"API Contract Review", "category":"api", "status":"planned", "mode":"analysis", "risk":"low", "description":"Review an OpenAPI contract for security design gaps."},
    {"id":"identity-flow-review", "name":"Identity Flow Review", "category":"identity", "status":"planned", "mode":"analysis", "risk":"low", "description":"Review OAuth/OIDC/JWT configuration and trust boundaries."},
    {"id":"cloud-config-review", "name":"Cloud Configuration Review", "category":"cloud", "status":"planned", "mode":"analysis", "risk":"low", "description":"Review exported cloud configuration and IAM policy artifacts."},
    {"id":"container-hardening-review", "name":"Container Hardening Review", "category":"container", "status":"planned", "mode":"analysis", "risk":"low", "description":"Review Docker and Kubernetes configuration artifacts."},
    {"id":"ad-architecture-review", "name":"Active Directory Architecture Review", "category":"ad", "status":"planned", "mode":"analysis", "risk":"medium", "description":"Review supplied AD topology and configuration evidence."},
    {"id":"network-exposure-review", "name":"Network Exposure Review", "category":"network", "status":"planned", "mode":"analysis", "risk":"medium", "description":"Review supplied network inventory and approved scan results."},
    {"id":"ai-application-review", "name":"AI Application Security Review", "category":"ai", "status":"planned", "mode":"analysis", "risk":"low", "description":"Review LLM, prompt, retrieval and tool permission boundaries."},
    {"id":"evidence-reporting", "name":"Evidence & Reporting", "category":"utility", "status":"active", "mode":"analysis", "risk":"low", "description":"Produce traceable findings with evidence provenance."}
]


def catalog() -> dict:
    result = []
    for key, name in CATEGORIES:
        skills = [s for s in SKILLS if s["category"] == key]
        result.append({"id": key, "name": name, "skill_count": len(skills),
                       "active_count": sum(1 for s in skills if s["status"] == "active"),
                       "status": "active" if any(s["status"] == "active" for s in skills) else "planned"})
    return {"category_count": len(result), "skill_count": len(SKILLS),
            "active_skills": sum(1 for s in SKILLS if s["status"] == "active"),
            "executable_skills": sum(1 for s in SKILLS if s["status"] == "active" and s["mode"] == "passive"),
            "categories": result, "skills": SKILLS}
