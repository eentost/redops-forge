import asyncio
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field

from . import store
from .catalog import catalog
from .planner import build_plan
from .policy import PolicyError, validate_target
from .runner import run_safe_http_review


@asynccontextmanager
async def lifespan(app: FastAPI):
    store.init_db()
    yield


app = FastAPI(
    title="RedOps Forge API",
    version="0.1.0",
    description="Scope-controlled red-team assessment MVP",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)
FRONTEND = Path(__file__).resolve().parents[2] / "frontend"
RUN_SEMAPHORE = asyncio.Semaphore(1)


class ScopeCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=3, max_length=100)
    allowed_targets: list[str] = Field(min_length=1, max_length=20)
    approved_by: str = Field(min_length=2, max_length=100)
    authorization_ref: str = Field(min_length=3, max_length=200)
    valid_until: str
    lab_mode: bool = False
    max_requests: int = Field(default=5, ge=1, le=10)


class RunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope_id: str
    target: str
    skill_ids: list[str] = Field(
        default_factory=lambda: [
            "web-surface-review",
            "http-security-headers",
            "cookie-attributes",
        ]
    )


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


@app.get("/assets/{name}")
def assets(name: str):
    if name not in {"app.js", "styles.css"}:
        raise HTTPException(404, "Asset not found")
    return FileResponse(FRONTEND / name)


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "redops-forge", "version": "0.1.0"}


@app.get("/api/v1/catalog")
def get_catalog():
    return catalog()


@app.post("/api/v1/plans")
def create_plan(payload: RunCreate):
    scope = store.one("SELECT * FROM scopes WHERE id=?", (payload.scope_id,))
    if not scope:
        raise HTTPException(404, "Scope not found")
    try:
        validate_target(
            payload.target,
            json.loads(scope["allowed_targets"]),
            scope["valid_until"],
            bool(scope["lab_mode"]),
        )
    except (PolicyError, ValueError) as exc:
        raise HTTPException(403, str(exc)) from exc
    active = {
        skill["id"]
        for skill in catalog()["skills"]
        if skill["status"] == "active" and skill["mode"] == "passive"
    }
    requested = set(payload.skill_ids)
    if not requested or not requested.issubset(active):
        raise HTTPException(400, "Only active MVP skills can be planned.")
    return build_plan(payload.target, sorted(requested), scope["max_requests"])


@app.get("/api/v1/scopes")
def list_scopes():
    items = store.rows("SELECT * FROM scopes ORDER BY created_at DESC")
    for item in items:
        item["allowed_targets"] = json.loads(item["allowed_targets"])
        item["lab_mode"] = bool(item["lab_mode"])
    return {"items": items}


@app.post("/api/v1/scopes")
def create_scope(payload: ScopeCreate):
    try:
        for target in payload.allowed_targets:
            validate_target(
                target,
                payload.allowed_targets,
                payload.valid_until,
                payload.lab_mode,
            )
    except (PolicyError, ValueError) as exc:
        raise HTTPException(400, str(exc)) from exc
    scope_id = str(uuid.uuid4())
    with store.connect() as db:
        db.execute(
            "INSERT INTO scopes VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                scope_id,
                payload.name,
                json.dumps(payload.allowed_targets),
                payload.approved_by,
                payload.authorization_ref,
                payload.valid_until,
                int(payload.lab_mode),
                payload.max_requests,
                store.now_iso(),
            ),
        )
    store.record_audit(
        payload.approved_by,
        "scope_created",
        "scope",
        scope_id,
        {
            "authorization_ref": payload.authorization_ref,
            "allowed_targets": payload.allowed_targets,
        },
    )
    return {"id": scope_id, "status": "approved_scope_registered"}


@app.get("/api/v1/runs")
def list_runs():
    runs = store.rows("SELECT * FROM runs ORDER BY started_at DESC LIMIT 100")
    for run in runs:
        run["summary"] = json.loads(run["summary"])
    return {"items": runs}


@app.post("/api/v1/runs")
async def create_run(payload: RunCreate):
    scope = store.one("SELECT * FROM scopes WHERE id=?", (payload.scope_id,))
    if not scope:
        raise HTTPException(404, "Scope not found")
    allowed_targets = json.loads(scope["allowed_targets"])
    try:
        validate_target(
            payload.target,
            allowed_targets,
            scope["valid_until"],
            bool(scope["lab_mode"]),
        )
    except (PolicyError, ValueError) as exc:
        store.record_audit(
            "operator",
            "run_blocked",
            "scope",
            payload.scope_id,
            {"target": payload.target, "reason": str(exc)},
        )
        raise HTTPException(403, str(exc)) from exc

    active = {
        skill["id"]
        for skill in catalog()["skills"]
        if skill["status"] == "active" and skill["mode"] == "passive"
    }
    requested = set(payload.skill_ids)
    if not requested or not requested.issubset(active):
        raise HTTPException(400, "Only active MVP skills can be executed.")

    run_id = str(uuid.uuid4())
    started = store.now_iso()
    with store.connect() as db:
        db.execute(
            "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?)",
            (run_id, payload.scope_id, payload.target, "running", started, None, "{}"),
        )
    store.record_audit(
        "operator",
        "run_started",
        "run",
        run_id,
        {"scope_id": payload.scope_id, "target": payload.target, "skills": sorted(requested)},
    )

    try:
        async with RUN_SEMAPHORE:
            result = await run_safe_http_review(
                run_id,
                payload.target,
                int(scope["max_requests"]),
                sorted(requested),
                allowed_targets,
                scope["valid_until"],
                bool(scope["lab_mode"]),
            )
        with store.connect() as db:
            db.execute(
                "UPDATE runs SET status=?, completed_at=?, summary=? WHERE id=?",
                (
                    "completed",
                    store.now_iso(),
                    json.dumps(result["summary"], sort_keys=True),
                    run_id,
                ),
            )
        store.add_evidence(run_id, "run_summary", result["summary"])
        store.record_audit("runner", "run_completed", "run", run_id, result["summary"])
        return {"id": run_id, **result}
    except Exception as exc:
        with store.connect() as db:
            db.execute(
                "UPDATE runs SET status=?, completed_at=?, summary=? WHERE id=?",
                (
                    "failed",
                    store.now_iso(),
                    json.dumps({"error_type": type(exc).__name__}),
                    run_id,
                ),
            )
        store.add_evidence(run_id, "execution_error", {"error_type": type(exc).__name__})
        store.record_audit(
            "runner",
            "run_failed",
            "run",
            run_id,
            {"error_type": type(exc).__name__},
        )
        raise HTTPException(502, f"Assessment failed: {type(exc).__name__}") from exc


@app.get("/api/v1/runs/{run_id}")
def get_run(run_id: str):
    run = store.one("SELECT * FROM runs WHERE id=?", (run_id,))
    if not run:
        raise HTTPException(404, "Run not found")
    run["summary"] = json.loads(run["summary"])
    findings = store.rows(
        "SELECT * FROM findings WHERE run_id=? ORDER BY created_at, rowid",
        (run_id,),
    )
    evidence = store.rows(
        "SELECT * FROM evidence WHERE run_id=? ORDER BY rowid",
        (run_id,),
    )
    for item in findings:
        item["evidence"] = json.loads(item["evidence"])
    for item in evidence:
        item["payload"] = json.loads(item["payload"])
    return {"run": run, "findings": findings, "evidence": evidence}


@app.get("/api/v1/runs/{run_id}/verify")
def verify_run_evidence(run_id: str):
    if not store.one("SELECT id FROM runs WHERE id=?", (run_id,)):
        raise HTTPException(404, "Run not found")
    return store.verify_evidence_chain(run_id)


@app.get("/api/v1/audit")
def audit_log():
    items = store.rows("SELECT * FROM audit ORDER BY created_at DESC, rowid DESC LIMIT 200")
    for item in items:
        item["details"] = json.loads(item["details"])
    return {"items": items}


@app.get("/api/v1/metrics")
def metrics():
    run_count = store.one("SELECT COUNT(*) AS n FROM runs")["n"]
    finding_count = store.one("SELECT COUNT(*) AS n FROM findings")["n"]
    scope_count = store.one("SELECT COUNT(*) AS n FROM scopes")["n"]
    active_count = store.one("SELECT COUNT(*) AS n FROM runs WHERE status='running'")["n"]
    return {
        "scopes": scope_count,
        "runs": run_count,
        "findings": finding_count,
        "active_runs": active_count,
    }


@app.get("/api/v1/reports/{run_id}")
def report(run_id: str):
    data = get_run(run_id)
    return {
        "report_version": "0.1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": "RedOps Forge",
        "evidence_integrity": store.verify_evidence_chain(run_id),
        **data,
    }
