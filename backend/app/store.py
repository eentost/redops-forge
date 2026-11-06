import hashlib
import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DB_PATH = os.getenv("REDOPS_DB_PATH", "/data/redops.db")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def init_db() -> None:
    with connect() as db:
        db.executescript(
            """
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS scopes (
                id TEXT PRIMARY KEY, name TEXT NOT NULL, allowed_targets TEXT NOT NULL,
                approved_by TEXT NOT NULL, authorization_ref TEXT NOT NULL,
                valid_until TEXT NOT NULL, lab_mode INTEGER NOT NULL DEFAULT 0,
                max_requests INTEGER NOT NULL DEFAULT 8, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runs (
                id TEXT PRIMARY KEY, scope_id TEXT NOT NULL, target TEXT NOT NULL,
                status TEXT NOT NULL, started_at TEXT NOT NULL, completed_at TEXT,
                summary TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY, run_id TEXT NOT NULL, code TEXT NOT NULL,
                severity TEXT NOT NULL, title TEXT NOT NULL, description TEXT NOT NULL,
                evidence TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY, run_id TEXT NOT NULL, kind TEXT NOT NULL,
                payload TEXT NOT NULL, previous_hash TEXT NOT NULL,
                sha256 TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit (
                id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
                object_type TEXT NOT NULL, object_id TEXT NOT NULL,
                details TEXT NOT NULL, created_at TEXT NOT NULL
            );
            """
        )


def record_audit(
    actor: str,
    action: str,
    object_type: str,
    object_id: str,
    details: dict[str, Any],
) -> None:
    with connect() as db:
        db.execute(
            "INSERT INTO audit VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                actor,
                action,
                object_type,
                object_id,
                json.dumps(details, sort_keys=True),
                now_iso(),
            ),
        )


def add_evidence(run_id: str, kind: str, payload: dict[str, Any]) -> dict[str, str]:
    with connect() as db:
        row = db.execute(
            "SELECT sha256 FROM evidence WHERE run_id=? ORDER BY rowid DESC LIMIT 1",
            (run_id,),
        ).fetchone()
        previous = row["sha256"] if row else "GENESIS"
        created = now_iso()
        canonical = json.dumps(
            {
                "run_id": run_id,
                "kind": kind,
                "payload": payload,
                "previous_hash": previous,
                "created_at": created,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(canonical.encode()).hexdigest()
        evidence_id = str(uuid.uuid4())
        db.execute(
            "INSERT INTO evidence VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                evidence_id,
                run_id,
                kind,
                json.dumps(payload, sort_keys=True),
                previous,
                digest,
                created,
            ),
        )
    return {
        "id": evidence_id,
        "sha256": digest,
        "previous_hash": previous,
        "created_at": created,
    }


def rows(query: str, args: tuple = ()) -> list[dict[str, Any]]:
    with connect() as db:
        return [dict(row) for row in db.execute(query, args).fetchall()]


def one(query: str, args: tuple = ()) -> dict[str, Any] | None:
    with connect() as db:
        row = db.execute(query, args).fetchone()
        return dict(row) if row else None


def verify_evidence_chain(run_id: str) -> dict[str, Any]:
    records = rows(
        "SELECT * FROM evidence WHERE run_id=? ORDER BY rowid",
        (run_id,),
    )
    previous = "GENESIS"
    checked = 0
    for record in records:
        payload = json.loads(record["payload"])
        canonical = json.dumps(
            {
                "run_id": run_id,
                "kind": record["kind"],
                "payload": payload,
                "previous_hash": previous,
                "created_at": record["created_at"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        expected = hashlib.sha256(canonical.encode()).hexdigest()
        if record["previous_hash"] != previous or record["sha256"] != expected:
            return {
                "valid": False,
                "checked_records": checked,
                "failed_record_id": record["id"],
            }
        previous = record["sha256"]
        checked += 1
    return {"valid": True, "checked_records": checked, "final_hash": previous}
