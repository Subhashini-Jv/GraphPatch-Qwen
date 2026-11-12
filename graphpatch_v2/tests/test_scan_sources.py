import pytest

pytest.importorskip("fastapi")
from fastapi import HTTPException  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from graphpatch_v2 import server  # noqa: E402

client = TestClient(server.app)


def test_github_url_forms():
    assert server.parse_github_url("https://github.com/apache/commons-io") == ("apache", "commons-io", None)
    assert server.parse_github_url("github.com/a/b.git") == ("a", "b", None)
    assert server.parse_github_url("https://github.com/a/b/tree/release/2.x") == ("a", "b", "release/2.x")
    for bad in ["https://evil.com/a/b", "https://github.com/a", "https://github.com/a/b?x=1", "file:///etc/passwd"]:
        with pytest.raises(HTTPException):
            server.parse_github_url(bad)


def test_paste_code_scan_and_report():
    r = client.post("/api/scan/code", json={"code": server.SAMPLE_JAVA, "cwe": "all"})
    assert r.status_code == 200, r.text
    meta = r.json()
    assert meta["name"] == "ArchiveExtractor.java" and meta["findings"]
    rep = client.get(f"/api/scan/{meta['id']}/report.html")
    assert rep.status_code == 200 and "ArchiveExtractor.extract" in rep.text


def test_paste_rejects_non_java():
    assert client.post("/api/scan/code", json={"code": "hello world"}).status_code == 400


def test_github_scan_uses_download(monkeypatch):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:  # GitHub zipballs wrap everything in one top folder
        z.writestr("owner-repo-abc123/src/main/java/demo/ArchiveExtractor.java", server.SAMPLE_JAVA)
    seen = {}
    monkeypatch.setattr(server, "download_github", lambda o, r, ref: seen.update(o=o, r=r, ref=ref) or buf.getvalue())
    r = client.post("/api/scan/github", json={"url": "https://github.com/owner/repo/tree/main"})
    assert r.status_code == 200, r.text
    assert seen == {"o": "owner", "r": "repo", "ref": "main"}
    assert r.json()["name"] == "owner/repo" and r.json()["findings"]
