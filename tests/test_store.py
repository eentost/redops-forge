import json
from backend.app import store

def test_evidence_hash_chain(tmp_path,monkeypatch):
    monkeypatch.setattr(store,"DB_PATH",str(tmp_path/"test.db"));store.init_db()
    first=store.add_evidence("run-1","probe",{"status":200})
    second=store.add_evidence("run-1","summary",{"count":1})
    assert first["previous_hash"]=="GENESIS"
    assert second["previous_hash"]==first["sha256"]
    assert len(first["sha256"])==64

def test_evidence_chain_verification(tmp_path,monkeypatch):
    monkeypatch.setattr(store,"DB_PATH",str(tmp_path/"verify.db"));store.init_db()
    store.add_evidence("run-verify","probe",{"status":204})
    store.add_evidence("run-verify","summary",{"findings":0})
    result=store.verify_evidence_chain("run-verify")
    assert result["valid"] is True and result["checked_records"]==2

def test_evidence_tampering_is_detected(tmp_path,monkeypatch):
    monkeypatch.setattr(store,"DB_PATH",str(tmp_path/"tamper.db"));store.init_db()
    store.add_evidence("run-tamper","probe",{"status":200})
    with store.connect() as db:
        db.execute("UPDATE evidence SET payload=? WHERE run_id=?",(json.dumps({"status":201}),"run-tamper"))
    result=store.verify_evidence_chain("run-tamper")
    assert result["valid"] is False
