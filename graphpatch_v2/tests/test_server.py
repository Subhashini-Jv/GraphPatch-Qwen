import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402


def test_sample_scan_finds_zip_slip(tmp_path, monkeypatch):
    monkeypatch.setattr("graphpatch_v2.server.UPLOADS", tmp_path)
    from graphpatch_v2.server import app
    c = TestClient(app)
    z = c.get("/api/sample").content
    r = c.post("/api/scan", files={"file": ("demo.zip", z, "application/zip")}, data={"cwe": "CWE-022"})
    assert r.status_code == 200
    f = r.json()["findings"]
    assert f and all(x["nodes"][0]["kind"] == "source" and x["nodes"][-1]["kind"] == "sink" for x in f)


def test_rejects_unsafe_zip(tmp_path, monkeypatch):
    import io
    import zipfile
    monkeypatch.setattr("graphpatch_v2.server.UPLOADS", tmp_path)
    from graphpatch_v2.server import app
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../evil.java", "class X {}")
    r = TestClient(app).post("/api/scan", files={"file": ("x.zip", buf.getvalue(), "application/zip")})
    assert r.status_code == 400


def test_rule_fix_without_key(tmp_path, monkeypatch):
    monkeypatch.setattr("graphpatch_v2.server.UPLOADS", tmp_path)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GP_LLM_API_KEY", raising=False)
    import time
    from graphpatch_v2.server import app
    c = TestClient(app)
    scan = c.post("/api/scan", files={"file": ("demo.zip", c.get("/api/sample").content, "application/zip")},
                  data={"cwe": "CWE-022"}).json()
    job = c.post(f"/api/scan/{scan['id']}/fix", json={"engine": "rule"}).json()
    for _ in range(100):
        j = c.get(f"/api/jobs/{job['id']}").json()
        if j["status"] != "running":
            break
        time.sleep(0.1)
    assert j["status"] == "done", j
    assert j["result"]["status"] == "closed" and j["result"]["llm_calls"] == 0 and "startsWith" in j["result"]["diff"]


def test_project_scan_drops_generic_code_injection_names():
    from graphpatch_v2.scanner import _real_finding
    from graphpatch_v2.taint import Finding
    f = lambda cwe, sink, src: Finding(cwe, "A.java", "A", "m", 1, sink, (src, f"SINK `{sink}` at line 1"))
    assert not _real_finding(f("CWE-094", "action.process(...)", "archive entry name `e.getName()` (line 1)"))
    assert not _real_finding(f("CWE-094", "parser.parseExpression(...)", "parameter `s` of public method m (line 1)"))
    assert _real_finding(f("CWE-094", "parser.parseExpression(...)", "untrusted input `request.getParameter(...)` (line 1)"))
    assert _real_finding(f("CWE-022", "new FileOutputStream(...)", "parameter `s` of public method m (line 1)"))


def test_library_check_endpoint(tmp_path, monkeypatch):
    import io
    import zipfile
    monkeypatch.setattr("graphpatch_v2.server.UPLOADS", tmp_path)
    seen = {}

    def fake_osv(deps, timeout=20):
        seen["deps"] = [(d.name, d.version) for d in deps]
        return [{"name": "org.apache.commons:commons-compress", "version": "1.14", "file": "pom.xml", "id": "GHSA-x",
                 "aliases": ["CVE-2018-11771"], "summary": "loop", "severity": "MODERATE", "fixed": ["1.18"],
                 "url": "https://osv.dev/vulnerability/GHSA-x"}]
    monkeypatch.setattr("graphpatch_v2.deps.check_osv", fake_osv)
    from graphpatch_v2.server import app
    pom = ("<project xmlns='http://maven.apache.org/POM/4.0.0'><dependencies><dependency><groupId>org.apache.commons</groupId>"
           "<artifactId>commons-compress</artifactId><version>1.14</version></dependency></dependencies></project>")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("pom.xml", pom)
        z.writestr("src/main/java/A.java", "public class A {}")
    c = TestClient(app)
    scan = c.post("/api/scan", files={"file": ("p.zip", buf.getvalue())}, data={"cwe": "all"}).json()
    d = c.get(f"/api/scan/{scan['id']}/libraries").json()
    assert seen["deps"] == [("org.apache.commons:commons-compress", "1.14")]
    assert d["libraries"] == 1 and d["vulnerable"] == 1 and d["vulns"][0]["aliases"] == ["CVE-2018-11771"]


def test_attack_tests_download(tmp_path, monkeypatch):
    import io
    import zipfile
    monkeypatch.setattr("graphpatch_v2.server.UPLOADS", tmp_path)
    from graphpatch_v2.server import app
    c = TestClient(app)
    scan = c.post("/api/scan", files={"file": ("demo.zip", c.get("/api/sample").content, "application/zip")},
                  data={"cwe": "CWE-022"}).json()
    r = c.get(f"/api/scan/{scan['id']}/attack-tests.zip")
    assert r.status_code == 200
    names = zipfile.ZipFile(io.BytesIO(r.content)).namelist()
    assert any(n.endswith("AttackTest.java") for n in names) and "README.txt" in names


def test_frontend_endpoints(tmp_path, monkeypatch):
    """The React frontend's endpoints: scan list, saved repair, original/patched source (and no path escape)."""
    monkeypatch.setattr("graphpatch_v2.server.UPLOADS", tmp_path)
    import time
    from graphpatch_v2.server import app
    c = TestClient(app)
    scan = c.post("/api/scan", files={"file": ("demo.zip", c.get("/api/sample").content, "application/zip")},
                  data={"cwe": "CWE-022"}).json()
    sid = scan["id"]
    row = next(s for s in c.get("/api/scans").json()["scans"] if s["id"] == sid)
    assert row["findings"] == len(scan["findings"]) and row["fix"] is None
    assert c.get(f"/api/scan/{sid}/fix").status_code == 404
    job = c.post(f"/api/scan/{sid}/fix", json={"engine": "rule"}).json()
    for _ in range(100):
        if c.get(f"/api/jobs/{job['id']}").json()["status"] != "running":
            break
        time.sleep(0.1)
    fix = c.get(f"/api/scan/{sid}/fix").json()
    assert fix["status"] == "closed" and fix["engine"] == "rule"
    path = next(l[6:] for l in fix["diff"].split("\n") if l.startswith("+++ b/"))
    a = c.get(f"/api/scan/{sid}/source", params={"path": path, "version": "original"}).json()["text"]
    b = c.get(f"/api/scan/{sid}/source", params={"path": path, "version": "patched"}).json()["text"]
    assert a != b and "normalize" in b
    assert c.get(f"/api/scan/{sid}/source", params={"path": "../../meta.json", "version": "original"}).status_code in (400, 404)
    assert next(s for s in c.get("/api/scans").json()["scans"] if s["id"] == sid)["fix"]["status"] == "closed"


def test_graph_endpoint_uses_networkx(tmp_path, monkeypatch):
    monkeypatch.setattr("graphpatch_v2.server.UPLOADS", tmp_path)
    import time
    from graphpatch_v2.server import app
    c = TestClient(app)
    sid = c.post("/api/scan", files={"file": ("demo.zip", c.get("/api/sample").content, "application/zip")},
                 data={"cwe": "CWE-022"}).json()["id"]
    g = c.get(f"/api/scan/{sid}/graph").json()
    assert g["summary"]["sources"] >= 1 and g["summary"]["reachable_sinks"] >= 1 and g["after"] is None
    assert g["hot_files"] and g["graph"]["links"]
    job = c.post(f"/api/scan/{sid}/fix", json={"engine": "rule"}).json()
    for _ in range(100):
        if c.get(f"/api/jobs/{job['id']}").json()["status"] != "running":
            break
        time.sleep(0.1)
    assert c.get(f"/api/scan/{sid}/graph").json()["after"]["reachable_sinks"] == 0
    assert b"graphml" in c.get(f"/api/scan/{sid}/taint-graph.graphml").content


def test_python_project_scan_and_agent_repair_with_scripted_model(tmp_path, monkeypatch):
    """A pasted Flask app: found, then repaired by the agent loop (scripted model) and checked by re-scanning."""
    pytest.importorskip("tree_sitter_python")
    import time
    from graphpatch_v2 import server

    class FakeLLM:
        def __init__(self, *a, **k):
            from graphpatch_v2.llm import Usage
            self.usage, self.timeout, self.max_attempts, self.on_retry, self.retry_empty = Usage(), 0, 0, None, False

        def chat(self, system, user, role="", json_mode=False):
            assert "Python" in system and "Java source level" not in user
            if role == "planner":
                return "- shell=True with request input: use an argument list"
            return ("FILE: download.py\n<<<<<<< SEARCH\n    os.system(\"ping -c 1 \" + host)\n=======\n"
                    "    subprocess.run([\"ping\", \"-c\", \"1\", shlex.quote(host)])\n>>>>>>> REPLACE\n")

    monkeypatch.setattr(server, "UPLOADS", tmp_path)
    monkeypatch.setattr(server, "LLM", FakeLLM)
    c = TestClient(server.app)
    code = ("import os, subprocess, shlex\nfrom flask import request\n\n"
            "def download():\n    host = request.args.get(\"host\")\n    os.system(\"ping -c 1 \" + host)\n")
    scan = c.post("/api/scan/code", json={"code": code}).json()
    assert scan["languages"] == {"python": 1} and [f["cwe"] for f in scan["findings"]] == ["CWE-078"]
    assert scan["findings"][0]["snippet"]["lines"][0].startswith("def download")
    job = c.post(f"/api/scan/{scan['id']}/fix", json={"engine": "agents"}).json()
    for _ in range(100):
        if c.get(f"/api/jobs/{job['id']}").json()["status"] != "running":
            break
        time.sleep(0.1)
    fix = c.get(f"/api/scan/{scan['id']}/fix").json()
    assert fix["status"] == "closed" and "shlex.quote(host)" in fix["diff"]


def test_paste_code_language_detection():
    from graphpatch_v2.server import guess_language
    assert guess_language("public class A {\n  void f() { int x = 1; }\n}") == "java"
    assert guess_language("import os\n\ndef f(x):\n    os.system(x)\n") == "python"
    assert guess_language("const fs = require('fs');\napp.get('/', (req, res) => res.send(req.query.q));") == "javascript"
