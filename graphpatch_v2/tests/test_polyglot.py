"""Python and JavaScript front ends (Tree-sitter + catalogues/python.yaml, javascript.yaml)."""
from pathlib import Path

import pytest

pytest.importorskip("tree_sitter_python")
from graphpatch_v2 import polyglot  # noqa: E402
from graphpatch_v2.scanner import risk, scan_repo, source_files  # noqa: E402

SAMPLES = Path(__file__).parent / "polyglot_samples"
ALL = ["CWE-022", "CWE-078", "CWE-079", "CWE-094"]


def _found(lang, file):
    return {(f.cwe, f.method) for f in polyglot.find_paths(SAMPLES, [file], ALL, lang)}


def test_python_flask_sources_sinks_and_guard():
    got = _found("python", "app.py")
    assert {("CWE-022", "download"), ("CWE-078", "ping"), ("CWE-079", "hello"), ("CWE-094", "calc")} <= got
    assert ("CWE-022", "unzip") in got                     # zip-slip through an archive member name
    assert not any(m == "safe_download" for _, m in got)   # realpath + startswith + abort is a guard


def test_javascript_express_sources_sinks_and_guard():
    got = _found("javascript", "server.js")
    assert {("CWE-022", "GET /file"), ("CWE-078", "POST /run"), ("CWE-079", "GET /greet"),
            ("CWE-079", "render"), ("CWE-094", "calc")} <= got
    assert not any(c == "CWE-022" and m == "GET /safe" for c, m in got)


def test_sanitizers_stop_taint(tmp_path):
    (tmp_path / "a.py").write_text("import os, shlex\nfrom flask import request\n"
                                   "def f():\n    os.system('ls ' + shlex.quote(request.args['d']))\n"
                                   "def g():\n    open(os.path.basename(request.args['n']))\n")
    (tmp_path / "b.js").write_text("const escape = require('escape-html');\n"
                                   "app.get('/x', (req, res) => res.send(escape(req.query.q)));\n")
    assert scan_repo(tmp_path, ALL) == []


def test_scan_repo_mixes_languages_and_scores_them(tmp_path):
    (tmp_path / "web.py").write_text("from flask import request\nimport os\ndef run():\n    os.system(request.args['c'])\n")
    (tmp_path / "srv.js").write_text("app.get('/e', (req, res) => { eval(req.body.code) })\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("import os\ndef t(x):\n    os.system(x)\n")
    langs = source_files(tmp_path)
    assert langs["python"] == ["web.py"] and langs["javascript"] == ["srv.js"]
    fs = scan_repo(tmp_path, ALL)
    assert {(f.file, f.cwe) for f in fs} == {("web.py", "CWE-078"), ("srv.js", "CWE-094")}
    assert all(risk(f)["level"] in ("critical", "high") for f in fs)


def test_units_and_parse_check():
    text = (SAMPLES / "server.js").read_text()
    names = [u.name for u in polyglot.units(text, "server.js")]
    assert "GET /file" in names and "render" in names
    assert polyglot.parses("def f(x):\n    return x\n", "python")
    assert not polyglot.parses("def f(x)\n    return x\n", "python")
