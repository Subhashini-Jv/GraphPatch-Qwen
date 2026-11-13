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


# ------------------------------------------------------------------ v3.5 fixes (end-to-end test, 13 Nov 2026)

def _scan(tmp_path, name, code):
    (tmp_path / name).write_text(code)
    return [(f.cwe, f.method, f.sink) for f in scan_repo(tmp_path, ALL)]


def test_js_send_file_with_constant_path_is_not_a_finding(tmp_path):
    # bug 1: the route's `res` parameter used to count as the tainted path
    code = ("const app = require('express')();\n"
            "app.get('/', (req, res) => res.sendFile('index.html', { root: __dirname }));\n"
            "app.get('/a', function (req, res) { res.download('report.pdf'); });\n")
    assert _scan(tmp_path, "a.js", code) == []


def test_js_send_file_with_user_path_is_still_a_finding(tmp_path):
    code = "const app = require('express')();\napp.get('/f', (req, res) => res.sendFile(req.query.p));\n"
    assert [c for c, _, _ in _scan(tmp_path, "a.js", code)] == ["CWE-022"]


def test_js_write_file_content_is_not_a_path(tmp_path):
    # bug 2: user data written to a fixed file is not path traversal; a user-chosen path still is
    code = ("const fs = require('fs');\nconst app = require('express')();\n"
            "app.post('/log', (req, res) => { fs.writeFile('/var/log/app.log', req.body.msg, () => res.end()); });\n"
            "app.post('/up', (req, res) => { fs.writeFileSync('/srv/' + req.body.name, req.body.data); });\n"
            "app.post('/mv', (req, res) => { fs.renameSync('/srv/a', req.body.to); });\n")
    got = {m for c, m, _ in _scan(tmp_path, "a.js", code) if c == "CWE-022"}
    assert got == {"POST /up", "POST /mv"}


def test_js_sanitised_upload_path_closes_the_finding(tmp_path):
    # the patch the repair loop could never get past the gate before v3.5
    code = ("const fs = require('fs');\nconst path = require('path');\nconst app = require('express')();\n"
            "app.post('/up', (req, res) => {\n  const dest = path.join('/srv', path.basename(req.body.filename));\n"
            "  fs.writeFile(dest, req.body.content, () => res.sendStatus(201));\n});\n")
    assert _scan(tmp_path, "a.js", code) == []


def test_python_flask_upload_save_is_a_finding(tmp_path):
    # bug 3: FileStorage.save(path) was not a sink
    code = ("import os\nfrom flask import Flask, request\nfrom werkzeug.utils import secure_filename\napp = Flask(__name__)\n"
            "@app.route('/up', methods=['POST'])\ndef up():\n    f = request.files['doc']\n"
            "    f.save(os.path.join('/srv/up', f.filename))\n    return 'ok'\n"
            "@app.route('/safe', methods=['POST'])\ndef safe():\n    f = request.files['doc']\n"
            "    f.save(os.path.join('/srv/up', secure_filename(f.filename)))\n    return 'ok'\n")
    assert _scan(tmp_path, "a.py", code) == [("CWE-022", "up", "f.save(...)")]


def test_python_save_without_a_path_argument_is_not_a_finding(tmp_path):
    # Django model/form .save() calls and overrides must not become path findings
    code = ("from django.db import models\nclass Doc(models.Model):\n"
            "    def save(self, *args, **kwargs):\n        super().save(*args, **kwargs)\n"
            "def view(request):\n    form = DocForm(request.POST)\n    obj = form.save(commit=False)\n    obj.save()\n")
    assert [c for c, _, _ in _scan(tmp_path, "a.py", code) if c == "CWE-022"] == []


def test_python_write_text_content_is_not_a_path(tmp_path):
    code = ("from pathlib import Path\nfrom flask import request\n"
            "def log():\n    Path('/var/log/app.log').write_text(request.form['msg'])\n"
            "def put():\n    Path('/srv', request.form['name']).write_text('x')\n")
    assert [(c, m) for c, m, _ in _scan(tmp_path, "a.py", code) if c == "CWE-022"] == [("CWE-022", "put")]


def test_js_open_method_on_other_objects_is_not_a_file_sink(tmp_path):
    # bug 4: modal.open(e), window.open(url), xhr.open(m, u) are not fs.open
    code = ("function show(e) { modalInstance.open(e); }\nfunction go(u) { window.open(u); }\n"
            "function req(m, u) { const x = new XMLHttpRequest(); x.open(m, u); }\n")
    assert _scan(tmp_path, "a.js", code) == []


def test_js_fs_open_is_still_a_file_sink(tmp_path):
    code = ("const fs = require('fs');\nconst { open } = require('fs/promises');\n"
            "function a(name) { fs.open(name, 'r', () => {}); }\nasync function b(name) { await open(name); }\n"
            "function c(name) { require('fs').promises.open(name); }\n")
    assert sorted(m for c, m, _ in _scan(tmp_path, "a.js", code)) == ["a", "b", "c"]


def test_js_vendor_folders_are_skipped(tmp_path):
    (tmp_path / "static" / "vendor").mkdir(parents=True)
    (tmp_path / "static" / "vendor" / "lib.js").write_text("function f(p) { require('fs').readFileSync(p); }\n")
    assert source_files(tmp_path)["javascript"] == []
