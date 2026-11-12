import json
import subprocess
import sys
import textwrap
from pathlib import Path

from graphpatch_v2 import codeql
from graphpatch_v2.dataset import CVE

VULN = textwrap.dedent("""\
    package demo;
    import java.io.*;
    public class Unzip {
        public void run(String dir, java.util.zip.ZipEntry e) throws IOException {
            File f = new File(dir, e.getName());
            new FileOutputStream(f).close();
        }
    }
""")
FIXED = VULN.replace("        new FileOutputStream", "        if (!f.getCanonicalPath().startsWith(dir)) throw new IOException();\n        new FileOutputStream")
assert FIXED != VULN


def _sarif(results, kind="path-problem"):
    """The shape `codeql database analyze --format=sarif-latest` writes (rules live in an extension pack)."""
    return {"runs": [{"tool": {"driver": {"name": "CodeQL", "rules": []},
                               "extensions": [{"name": "codeql/java-queries", "rules": [
                                   {"id": "java/zipslip", "properties": {"kind": kind, "tags": ["security", "external/cwe/cwe-022"]}},
                                   {"id": "java/xss", "properties": {"kind": "path-problem", "tags": ["security", "external/cwe/cwe-079"]}}]}]},
                      "results": results}]}


def _loc(uri, line):
    return {"physicalLocation": {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}, "region": {"startLine": line}}}


def _result(rule, sink, source, uri="src/main/java/demo/Unzip.java"):
    return {"ruleId": rule, "locations": [_loc(uri, sink)],
            "codeFlows": [{"threadFlows": [{"locations": [{"location": _loc(uri, source)}, {"location": _loc(uri, sink)}]}]}]}


def _tree(tmp_path, text):
    f = tmp_path / "src/main/java/demo/Unzip.java"
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)
    return tmp_path


def test_parse_keeps_only_the_cwe_and_target_files(tmp_path):
    src = _tree(tmp_path, VULN)
    s = _sarif([_result("java/zipslip", 6, 5), _result("java/xss", 6, 5),
                _result("java/zipslip", 3, 2, uri="src/main/java/demo/Other.java")])
    alerts = codeql.parse_sarif(s, "CWE-022", src, ["src/main/java/demo/Unzip.java"])
    assert len(alerts) == 1
    a = alerts[0]
    assert (a.rule, a.file, a.line, a.source_line) == ("java/zipslip", "src/main/java/demo/Unzip.java", 6, 5)
    assert "new FileOutputStream(f).close();" in a.key      # keyed by code text, not only by line number


def test_key_survives_a_line_shift(tmp_path):
    before = codeql.parse_sarif(_sarif([_result("java/zipslip", 6, 5)]), "CWE-022", _tree(tmp_path / "a", VULN))
    shifted = "\n" + VULN                                    # same code, one line lower
    after = codeql.parse_sarif(_sarif([_result("java/zipslip", 7, 6)]), "CWE-022", _tree(tmp_path / "b", shifted))
    assert {x.key for x in before} == {x.key for x in after}


def test_non_path_queries_are_ignored(tmp_path):
    assert codeql.parse_sarif(_sarif([_result("java/zipslip", 6, 5)], kind="problem"), "CWE-022", _tree(tmp_path, VULN)) == []


def test_absolute_file_uris_become_relative(tmp_path):
    src = _tree(tmp_path, VULN)
    uri = (src / "src/main/java/demo/Unzip.java").resolve().as_uri()
    a = codeql.parse_sarif(_sarif([_result("java/zipslip", 6, 5, uri=uri)]), "CWE-022", src, ["src/main/java/demo/Unzip.java"])
    assert [x.file for x in a] == ["src/main/java/demo/Unzip.java"]


def test_combine_counts_new_judgeable_cves():
    jl = [{"slug": "a", "cwe": "CWE-022", "reduced_by_fix": "True"}, {"slug": "b", "cwe": "CWE-079", "reduced_by_fix": "False"},
          {"slug": "c", "cwe": "CWE-079", "reduced_by_fix": "False"}]
    cq = [{"slug": "a", "cwe": "CWE-022", "reduced_by_fix": True, "status": "ok"},
          {"slug": "b", "cwe": "CWE-079", "reduced_by_fix": True, "status": "ok"},
          {"slug": "c", "cwe": "CWE-079", "status": "error: boom"}]
    t = codeql.combine(cq, jl)
    assert t["CWE-022"] == {"cves": 1, "javalang": 1, "codeql": 1, "codeql_only": 0, "either": 1, "codeql_checked": 1}
    assert t["CWE-079"]["codeql_only"] == 1 and t["CWE-079"]["either"] == 1 and t["CWE-079"]["codeql_checked"] == 1


def _git(cwd, *a):
    subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True)


def _project(tmp_path):
    # a real git project with a vulnerable commit and a fix commit, served as the CVE's "GitHub" remote
    up = tmp_path / "upstream"
    _tree(up, VULN)
    _git(up, "init", "-q")
    _git(up, "add", ".")
    _git(up, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "vuln")
    buggy = subprocess.run(["git", "rev-parse", "HEAD"], cwd=up, capture_output=True, text=True).stdout.strip()
    _tree(up, FIXED)
    _git(up, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "fix")
    fix = subprocess.run(["git", "rev-parse", "HEAD"], cwd=up, capture_output=True, text=True).stdout.strip()
    root = tmp_path / "gp_runs"
    cache = root / "cache" / "demo__unzip"
    cache.parent.mkdir(parents=True)
    _git(tmp_path, "clone", "-q", "--no-checkout", str(up), str(cache))

    # fake codeql: "database create" records the source root; "analyze" reports a path only on vulnerable code
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps(_sarif([_result("java/zipslip", 6, 5)])))
    fake = tmp_path / "fakecodeql.py"
    fake.write_text(textwrap.dedent(f"""\
        import json, sys, pathlib
        a = sys.argv[1:]
        if a[:2] == ["database", "create"]:
            db = pathlib.Path(a[2]); db.mkdir(parents=True, exist_ok=True)
            src = [x.split("=", 1)[1] for x in a if x.startswith("--source-root=")][0]
            (db / "src.txt").write_text(src)
        elif a[:2] == ["database", "analyze"]:
            src = pathlib.Path((pathlib.Path(a[2]) / "src.txt").read_text())
            out = [x.split("=", 1)[1] for x in a if x.startswith("--output=")][0]
            sarif = json.loads(pathlib.Path(r"{alert}").read_text())
            if "getCanonicalPath" in (src / "src/main/java/demo/Unzip.java").read_text():
                sarif["runs"][0]["results"] = []
            pathlib.Path(out).write_text(json.dumps(sarif))
    """))
    exe = tmp_path / ("codeql.cmd" if sys.platform == "win32" else "codeql")
    exe.write_text(f'@"{sys.executable}" "{fake}" %*' if sys.platform == "win32" else f'#!/bin/sh\nexec "{sys.executable}" "{fake}" "$@"\n')
    exe.chmod(0o755)
    return root, buggy, fix, exe


def test_calibrate_end_to_end_with_a_fake_codeql(tmp_path):
    root, buggy, fix, exe = _project(tmp_path)


    cve = CVE(slug="demo__unzip_CVE-0000-0001_1.0", cve_id="CVE-0000-0001", cwe="CWE-022", cwe_name="Path Traversal",
              repo_url="https://github.com/demo/unzip", buggy_commit=buggy, fix_commits=[fix],
              fix_rows=[{"file": "src/main/java/demo/Unzip.java", "method": "run", "signature": "run(String, ZipEntry)"}])
    rows = codeql.calibrate(str(exe), [cve], root)
    r = rows[0]
    assert r["status"] == "ok", r
    assert (r["buggy_paths"], r["fixed_paths"], r["detected"], r["cleared_by_fix"], r["reduced_by_fix"], r["fewer_after_fix"]) == (1, 0, True, True, True, True)
    assert not (root / "codeql" / cve.slug / "buggy" / "src").exists()          # source trees are cleaned up
    assert (root / "results" / "calibration_codeql.csv").read_text().count("\n") == 2
    # --skip-done does not run CodeQL again
    exe.write_text("#!/bin/sh\nexit 3\n" if sys.platform != "win32" else "@exit /b 3")
    assert codeql.calibrate(str(exe), [cve], root, skip_done=True)[0]["status"] == "ok"
    # a CodeQL step that runs too long is recorded as timeout and not retried by --skip-done
    cve2 = CVE(slug="demo__unzip_CVE-0000-0002_1.0", cve_id="CVE-0000-0002", cwe="CWE-022", cwe_name="Path Traversal",
               repo_url="https://github.com/demo/unzip", buggy_commit=buggy, fix_commits=[fix],
               fix_rows=[{"file": "src/main/java/demo/Unzip.java", "method": "run", "signature": "run(String, ZipEntry)"}])
    exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" -c "import time; time.sleep(30)"\n' if sys.platform != "win32"
                   else f'@"{sys.executable}" -c "import time; time.sleep(30)"')
    r2 = codeql.calibrate(str(exe), [cve2], root, skip_done=True, timeout=2)[0]
    assert r2["status"].startswith("timeout") and r2["seconds"] < 20, r2
    assert codeql.calibrate(str(exe), [cve2], root, skip_done=True, timeout=2)[0]["status"].startswith("timeout")
    # --exclude records the CVE without running anything
    cve3 = CVE(slug="demo__unzip_CVE-0000-0003_1.0", cve_id="CVE-0000-0003", cwe="CWE-022", cwe_name="Path Traversal",
               repo_url="https://github.com/demo/unzip", buggy_commit=buggy, fix_commits=[fix], fix_rows=cve2.fix_rows)
    r3 = codeql.calibrate(str(exe), [cve3], root, skip_done=True, exclude=["CVE-0000-0003"])[0]
    assert r3["status"].startswith("skipped") and r3["seconds"] < 2
    # the CSV keeps every CVE run so far, not only the last run's selection
    assert (root / "results" / "calibration_codeql.csv").read_text().count("\n") == 4


def test_timeout_kills_child_processes_holding_the_output(tmp_path):
    # the parent exits on kill, but a child it started keeps stdout open: the old code waited forever here
    import time
    t = time.time()
    try:
        codeql._run(["sh", "-c", "sleep 60 & sleep 60"] if sys.platform != "win32" else
                    ["cmd", "/c", f'start /b "" "{sys.executable}" -c "import time; time.sleep(60)" & ping -n 60 127.0.0.1'], 2)
        assert False, "should time out"
    except subprocess.TimeoutExpired:
        pass
    assert time.time() - t < 30


def test_related_cwe_queries_count(tmp_path):
    # Struts OGNL injection is a CWE-094 CVE, but CodeQL tags java/ognl-injection as CWE-917
    s = _sarif([_result("java/ognl-injection", 6, 5)])
    s["runs"][0]["tool"]["extensions"][0]["rules"].append(
        {"id": "java/ognl-injection", "properties": {"kind": "path-problem", "tags": ["security", "external/cwe/cwe-917"]}})
    assert len(codeql.parse_sarif(s, "CWE-094", _tree(tmp_path, VULN))) == 1
    assert codeql.parse_sarif(s, "CWE-079", tmp_path) == []


def test_vul4j_uses_its_own_branch_and_overlays_the_human_patch(tmp_path):
    """As `vul4j checkout`: vulnerable = head of the VUL4J-n branch in the vul4j repo, fixed = that tree with
    the human patch's files from the fix commit."""
    root, buggy, fix, exe = _project(tmp_path)
    up = tmp_path / "upstream"
    # Vul4J's branch: the fix commit, then a commit putting the vulnerable file back (plus an unrelated build tweak)
    _git(up, "checkout", "-qb", "VUL4J-9998")
    _tree(up, VULN)
    (up / "pom.xml").write_text("<project/>")
    _git(up, "add", ".")
    _git(up, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "vulnerable")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=up, capture_output=True, text=True).stdout.strip()
    _git(up, "checkout", "-q", "-")
    _git(tmp_path, "clone", "-q", "--no-checkout", str(up), str(root / "cache" / "tuhh-softsec__vul4j"))
    cve = CVE(slug="VUL4J-9998", cve_id="CVE-0000-0008", cwe="CWE-022", cwe_name="Path Traversal",
              repo_url="https://github.com/demo/unzip", buggy_commit="vulnerable", fix_commits=[fix], fix_rows=[])
    r = codeql.calibrate(str(exe), [cve], root, name="calibration_codeql_vul4j")[0]
    assert r["status"] == "ok", r
    assert r["source"] == "vul4j-branch" and cve.buggy_commit == head and cve.repo_url == codeql.VUL4J_REPO
    assert cve.target_files == ["src/main/java/demo/Unzip.java"]
    assert (r["buggy_paths"], r["fixed_paths"], r["cleared_by_fix"]) == (1, 0, True)


def test_vul4j_without_a_branch_falls_back_to_the_parent_commit(tmp_path):
    """No VUL4J-n branch: the vulnerable code is the fix commit's parent in the project's repository."""
    root, buggy, fix, exe = _project(tmp_path)
    _git(tmp_path, "clone", "-q", "--no-checkout", str(tmp_path / "upstream"), str(root / "cache" / "tuhh-softsec__vul4j"))
    cve = CVE(slug="VUL4J-9999", cve_id="CVE-0000-0009", cwe="CWE-022", cwe_name="Path Traversal",
              repo_url="https://github.com/demo/unzip", buggy_commit="vulnerable", fix_commits=[fix], fix_rows=[])
    r = codeql.calibrate(str(exe), [cve], root, name="calibration_codeql_vul4j")[0]
    assert r["status"] == "ok", r
    assert cve.buggy_commit == buggy and cve.target_files == ["src/main/java/demo/Unzip.java"] and r["source"] == "project-parent"
    assert (r["buggy_paths"], r["fixed_paths"], r["cleared_by_fix"]) == (1, 0, True)
    assert (root / "results" / "calibration_codeql_vul4j.csv").exists()
    assert not (root / "results" / "calibration_codeql.csv").exists()


def test_vul4j_selection_and_fix_files():
    from graphpatch_v2.vul4j_bench import Vul4JDataset
    bench = Path(codeql.__file__).parent / "benchmarks"
    judgeable = codeql._ids(bench / "vul4j_judgeable.txt")
    assert len(judgeable) == 65
    cves = [c for c in Vul4JDataset().select(None) if c.slug in judgeable and c.cwe in codeql.VUL4J_TAINT_CWES]
    assert len(cves) == 24 and set(codeql._ids(bench / "vul4j_graph_set.txt")) <= {c.slug for c in cves}
    files = json.loads(codeql.VUL4J_FIX_FILES.read_text())
    assert files["VUL4J-41"] == ["src/main/java/org/codehaus/plexus/archiver/AbstractUnArchiver.java"]


def test_cve_deadline_stops_a_cve_whose_steps_are_each_under_the_step_limit(tmp_path):
    root, buggy, fix, exe = _project(tmp_path)
    exe.write_text(f'#!/bin/sh\nexec "{sys.executable}" -c "import time; time.sleep(30)"\n' if sys.platform != "win32"
                   else f'@"{sys.executable}" -c "import time; time.sleep(30)"')
    cve = CVE(slug="demo__unzip_CVE-0000-0004_1.0", cve_id="CVE-0000-0004", cwe="CWE-022", cwe_name="Path Traversal",
              repo_url="https://github.com/demo/unzip", buggy_commit=buggy, fix_commits=[fix],
              fix_rows=[{"file": "src/main/java/demo/Unzip.java", "method": "run", "signature": "run(String, ZipEntry)"}])
    r = codeql.calibrate(str(exe), [cve], root, timeout=600, cve_timeout=2)[0]
    assert r["status"].startswith("timeout") and r["seconds"] < 20, r
    assert codeql.DEADLINE is None


def test_slow_step_prints_still_running(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(codeql, "HEARTBEAT", 1)
    r = codeql._run([sys.executable, "-c", "import time; time.sleep(2.5); print('done')"], 30)
    assert r.stdout.strip() == "done" and "still running" in capsys.readouterr().out
