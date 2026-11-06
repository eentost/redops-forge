from datetime import datetime,timedelta,timezone
from unittest.mock import patch
import socket
from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app import store

def test_scope_and_plan_api(tmp_path,monkeypatch):
    monkeypatch.setattr(store,"DB_PATH",str(tmp_path/"api.db"))
    fake_dns=[(socket.AF_INET,socket.SOCK_STREAM,6,"",("93.184.216.34",443))]
    with patch("backend.app.policy.socket.getaddrinfo",return_value=fake_dns):
        with TestClient(app) as client:
            expiry=(datetime.now(timezone.utc)+timedelta(days=1)).isoformat()
            created=client.post("/api/v1/scopes",json={"name":"Approved staging assessment","allowed_targets":["https://example.com"],"approved_by":"Security owner","authorization_ref":"ROE-TEST-001","valid_until":expiry,"lab_mode":False,"max_requests":3})
            assert created.status_code==200
            scope_id=created.json()["id"]
            plan=client.post("/api/v1/plans",json={"scope_id":scope_id,"target":"https://example.com/","skill_ids":["web-surface-review","http-security-headers"]})
            assert plan.status_code==200 and len(plan.json()["steps"])==2
            blocked=client.post("/api/v1/plans",json={"scope_id":scope_id,"target":"https://not-allowed.example","skill_ids":["web-surface-review"]})
            assert blocked.status_code==403

def test_dashboard_and_catalog(tmp_path,monkeypatch):
    monkeypatch.setattr(store,"DB_PATH",str(tmp_path/"dashboard.db"))
    with TestClient(app) as client:
        assert client.get("/").status_code==200
        assert client.get("/assets/app.js").status_code==200
        catalog=client.get("/api/v1/catalog").json()
        assert catalog["category_count"]==23
