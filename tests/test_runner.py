import asyncio
from backend.app import store
from backend.app.runner import run_safe_http_review

def test_safe_runner_records_metadata_without_body(tmp_path,monkeypatch):
    monkeypatch.setattr(store,"DB_PATH",str(tmp_path/"runner.db"));store.init_db()
    async def scenario():
        async def handler(reader,writer):
            await reader.readuntil(b"\r\n\r\n")
            body=b"private-response-body"
            response=(b"HTTP/1.1 200 OK\r\nContent-Length: "+str(len(body)).encode()+b"\r\nContent-Type: text/plain\r\nX-Content-Type-Options: nosniff\r\nSet-Cookie: session=secret; Path=/\r\nConnection: close\r\n\r\n"+body)
            writer.write(response);await writer.drain();writer.close();await writer.wait_closed()
        server=await asyncio.start_server(handler,"127.0.0.1",0);port=server.sockets[0].getsockname()[1]
        try:
            result=await run_safe_http_review("run-test",f"http://127.0.0.1:{port}/",1,["web-surface-review","http-security-headers","cookie-attributes"],[f"http://127.0.0.1:{port}"],"2099-01-01T00:00:00+00:00",True)
            assert result["summary"]["request_count"]==1
            assert result["responses"][0]["body_downloaded"] is False
            evidence=store.rows("SELECT payload FROM evidence WHERE run_id=?",("run-test",))
            joined=" ".join(row["payload"] for row in evidence)
            assert "private-response-body" not in joined and "session=secret" not in joined
            assert any(f["code"]=="COOKIE_ATTRIBUTES" for f in result["findings"])
            assert store.verify_evidence_chain("run-test")["valid"] is True
        finally:
            server.close();await server.wait_closed()
    asyncio.run(scenario())
