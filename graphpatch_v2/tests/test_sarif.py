"""SARIF export: the demo project gives one result per CWE, at the sink line, in SARIF 2.1.0 shape."""

import json
from pathlib import Path

from graphpatch_v2.sarif import main, to_sarif
from graphpatch_v2.scanner import CWE_NAMES, scan_repo

DEMO = Path(__file__).resolve().parent.parent / "github" / "demo"


def test_demo_findings_become_results(tmp_path):
    doc = to_sarif(scan_repo(DEMO, list(CWE_NAMES)), list(CWE_NAMES))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert [r["id"] for r in run["tool"]["driver"]["rules"]] == [f"graphpatch/{c}" for c in CWE_NAMES]
    got = {(r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]) for r in run["results"]}
    assert got == {("graphpatch/CWE-022", "src/main/java/demo/Unzip.java"),
                   ("graphpatch/CWE-078", "src/main/java/demo/Ping.java")}
    for r in run["results"]:
        assert run["tool"]["driver"]["rules"][r["ruleIndex"]]["id"] == r["ruleId"]


def test_cli_writes_file_and_fail_flag(tmp_path):
    out = tmp_path / "out.sarif"
    assert main([str(DEMO), "--out", str(out), "--cwe", "CWE-022"]) == 0
    assert len(json.loads(out.read_text())["runs"][0]["results"]) == 1
    assert main([str(DEMO), "--out", str(out), "--fail-on-findings"]) == 1


def test_web_app_sarif_download(tmp_path, monkeypatch):
    import io, zipfile
    import pytest
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    monkeypatch.setattr("graphpatch_v2.server.UPLOADS", tmp_path)
    from graphpatch_v2.server import app
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for p in DEMO.rglob("*.java"):
            z.write(p, p.relative_to(DEMO).as_posix())
    c = TestClient(app)
    scan = c.post("/api/scan", files={"file": ("demo.zip", buf.getvalue())}, data={"cwe": "all"}).json()
    r = c.get(f"/api/scan/{scan['id']}/graphpatch.sarif")
    assert r.status_code == 200
    assert {x["ruleId"] for x in r.json()["runs"][0]["results"]} == {"graphpatch/CWE-022", "graphpatch/CWE-078"}
