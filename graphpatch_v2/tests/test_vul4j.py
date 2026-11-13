"""Vul4J adapter, end to end through pipeline.run_cve, with a fake `vul4j` command that behaves like
the real one (checkout layout, compile.log, testing_results.json)."""

import csv
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from graphpatch_v2 import vul4j_bench
from graphpatch_v2.pipeline import Config, run_cve

VULN = textwrap.dedent("""\
    package demo;
    import java.io.*;
    import java.util.zip.*;
    public class Unzip {
        public void extract(File dir, ZipInputStream zin) throws IOException {
            ZipEntry entry = zin.getNextEntry();
            File file = new File(dir, entry.getName());
            OutputStream out = new FileOutputStream(file);
            out.close();
        }
    }
""")
FIXED = VULN.replace("        OutputStream out", "        if (!file.getCanonicalPath().startsWith(dir.getCanonicalPath())) throw new IOException(\"bad\");\n        OutputStream out")
POV = "package demo;\npublic class UnzipTest { /* zip-slip PoV */ }\n"

FAKE = r'''
import json, os, shutil, subprocess, sys
from pathlib import Path
a = sys.argv[1:]
cmd = a[0]
def opt(name):
    return a[a.index(name) + 1]
if cmd == "checkout":
    d = Path(opt("-d")); data = json.loads(Path(os.environ["FAKE_VUL4J_DATA"]).read_text())
    for rel, text in data["tree"].items():
        p = d / rel; p.parent.mkdir(parents=True, exist_ok=True); p.write_text(text)
    v = d / "VUL4J"; (v / "human_patch").mkdir(parents=True); (v / "vulnerable").mkdir()
    (v / "vulnerability_info.json").write_text(json.dumps({"vul_id": data["id"]}))
    (v / "human_patch" / "Unzip.java").write_text(data["fixed"])
    (v / "human_patch" / "paths.json").write_text(json.dumps({"Unzip.java": "src/main/java/demo/Unzip.java"}))
    (v / "vulnerable" / "Unzip.java").write_text(data["tree"]["src/main/java/demo/Unzip.java"])
    g = lambda *x: subprocess.run(["git", *x], cwd=d, check=True, capture_output=True)
    g("init", "-q"); g("add", "-A"); g("-c", "user.name=v", "-c", "user.email=v@v", "commit", "-qm", "vulnerable")
    (d / "src/main/java/demo/Unzip.java").write_text(data["fixed"])
    g("-c", "user.name=v", "-c", "user.email=v@v", "commit", "-qam", "human_patch"); g("checkout", "-q", "HEAD~1")
    sys.exit(0)
d = Path(opt("-d")); code = (d / "src/main/java/demo/Unzip.java").read_text()
log = d / "VUL4J" / ("compile.log" if cmd == "compile" else "testing.log")
with open(os.environ["FAKE_VUL4J_CALLS"], "a") as f:
    f.write(" ".join(a[:1] + a[3:]) + "\n")
if cmd == "compile":
    ok = code.count("{") == code.count("}")
    log.write_text("[INFO] BUILD SUCCESS\n" if ok else "[ERROR] /w/src/main/java/demo/Unzip.java:[5,1] error: reached end of file\n")
    sys.exit(0 if ok else 1)
if cmd == "test":
    batch = opt("-b"); pov_present = any((d / f).exists() for f in ("src/test/java/demo/UnzipTest.java", "src/test/groovy/demo/UnzipTest.groovy"))
    fixed = "startsWith" in code
    fails, passes = [], []
    if batch == "all":
        (fails if "BREAK" in code else passes).append(("demo.OtherTest", "works"))
    if pov_present:
        (passes if fixed else fails).append(("demo.UnzipTest", "zipSlip"))
    log.write_text("tests ran\n")
    (d / "VUL4J" / "testing_results.json").write_text(json.dumps({"tests": {
        "overall_metrics": {"number_running": len(fails) + len(passes), "number_failing": len(fails), "number_error": 0},
        "failures": [{"test_class": c, "test_method": m, "is_error": False} for c, m in fails],
        "passing_tests": [f"{c}#{m}" for c, m in passes], "skipping_tests": []}}))
    sys.exit(0)
sys.exit(2)
'''


@pytest.fixture
def bench(tmp_path, monkeypatch):
    fake = tmp_path / "fakevul4j.py"
    fake.write_text(FAKE)
    data = tmp_path / "fake_data.json"
    data.write_text(json.dumps({"id": "VUL4J-99", "fixed": FIXED, "tree": {
        "pom.xml": "<project/>", "src/main/java/demo/Unzip.java": VULN, "src/test/java/demo/UnzipTest.java": POV,
        "src/test/java/demo/OtherTest.java": "package demo;\npublic class OtherTest {}\n"}}))
    calls = tmp_path / "calls.txt"
    monkeypatch.setenv("GP_VUL4J_CMD", f"{sys.executable} {fake}")
    monkeypatch.setenv("FAKE_VUL4J_DATA", str(data))
    monkeypatch.setenv("FAKE_VUL4J_CALLS", str(calls))
    monkeypatch.setenv("VUL4J_GIT", str(tmp_path / "no-vul4j-git"))
    rows = tmp_path / "vul4j.csv"
    fields = ["vul_id", "cve_id", "cwe_id", "cwe_name", "repo_slug", "human_patch", "build_system", "compliance_level",
              "failing_tests", "failing_module", "test"]
    with open(rows, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerow({"vul_id": "VUL4J-99", "cve_id": "CVE-2099-0001", "cwe_id": "CWE-22", "cwe_name": "Path Traversal",
                    "repo_slug": "demo/unzip", "human_patch": "https://github.com/demo/unzip/commit/abc123",
                    "build_system": "Maven", "compliance_level": "8", "failing_tests": "demo.UnzipTest#zipSlip",
                    "failing_module": "root", "test": "src/test/java"})
        w.writerow({**{k: "" for k in fields}, "vul_id": "VUL4J-100-S", "failing_tests": ""})
    ds = vul4j_bench.Vul4JDataset(rows)
    cfg = Config(root=tmp_path / "gp_runs", out=tmp_path / "gp_runs" / "results_vul4j" / "artifacts")
    return ds, cfg, calls


def test_dataset_keeps_only_pov_entries(bench):
    ds, _, _ = bench
    assert list(ds.cves) == ["VUL4J-99"]
    c = ds.get("CVE-2099-0001")
    assert (c.cwe, c.repo_url, c.fix_commits) == ("CWE-022", "https://github.com/demo/unzip", ["abc123"])
    assert vul4j_bench.norm_cwe("Not Mapping") == "CWE-NONE"


def test_model_never_sees_the_fix_or_the_pov_tests(bench):
    ds, cfg, _ = bench
    cve = ds.get("VUL4J-99")
    ws = ds.make_workspace(cve, cfg.root).prepare()
    assert cve.target_files == ["src/main/java/demo/Unzip.java"]
    assert not (ws.path / "VUL4J" / "human_patch").exists()
    assert not (ws.path / "src/test/java/demo/UnzipTest.java").exists()
    assert (ws.path / "src/test/java/demo/OtherTest.java").exists()
    log = subprocess.run(["git", "log", "--all", "--format=%s"], cwd=ws.path, capture_output=True, text=True).stdout
    assert "human_patch" not in log and log.count("\n") == 1
    assert "startsWith" not in subprocess.run(["git", "grep", "-I", "startsWith", "--", "."], cwd=ws.path, capture_output=True, text=True).stdout
    assert ws.hidden not in (ws.path, *ws.path.parents) and ws.path not in ws.hidden.parents
    # prepare again reuses the checkout
    ds.make_workspace(cve, cfg.root).prepare()


def test_oracle_verifies_and_noop_does_not(bench):
    ds, cfg, calls = bench
    cve = ds.get("VUL4J-99")
    r = run_cve(cve, ds, "oracle", cfg)
    assert r["status"] == "verified", r
    assert (r["pov_ok"], r["pov_usable"], r["paths_before"], r["docker"]) == (True, True, 1, "vul4j-image")
    assert r["graph_eval_ok"] is True
    r = run_cve(cve, ds, "noop", cfg)
    assert r["status"] == "plausible" and r["pov_ok"] is False and r["graph_eval_ok"] is False
    # the baseline and the PoV check are run once per CVE, not per mode
    log = open(calls).read()
    assert log.count("test -b all") == 3     # baseline once, then one check per mode
    assert log.count("test -b povs") == 4    # PoV sanity check once (vulnerable + human fix), then once per mode


def test_rule_fix_is_judged_by_the_pov_test(bench):
    ds, cfg, _ = bench
    r = run_cve(ds.get("VUL4J-99"), ds, "rule", cfg)
    assert r["status"] == "verified" and r["pov_ok"] is True, r
    diff = (cfg.out / "rule" / "VUL4J-99" / "final.diff").read_text()
    assert "startsWith" in diff and "UnzipTest" not in diff


def test_broken_patch_is_rejected_but_pov_is_still_recorded(bench, monkeypatch):
    ds, cfg, _ = bench
    from graphpatch_v2 import pipeline
    patch = ('FILE: src/main/java/demo/Unzip.java\n<<<<<<< SEARCH\n        out.close();\n=======\n'
             '        out.close(); // BREAK\n        if (!file.toPath().normalize().startsWith(dir.toPath())) throw new IOException();\n>>>>>>> REPLACE\n')

    class FakeLLM:
        model = "fake"
        usage = type("U", (), {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0})()
        def chat(self, system, prompt, role="", json_mode=False):
            return patch
    cfg.llm = FakeLLM()
    r = run_cve(ds.get("VUL4J-99"), ds, "single", cfg)
    assert r["status"] == "rejected" and r["stage"] == "tests" and r["new_test_failures"] == 1, r
    assert r["compile_ok"] is True and r["pov_ok"] is True     # Vul4J's own protocol would count it


def test_groovy_pov_test_is_found_and_hidden(bench):
    # VUL4J-22 (Shiro): the PoV class is a Groovy test under src/test/groovy
    ds, cfg, _ = bench
    data = json.loads(Path(os.environ["FAKE_VUL4J_DATA"]).read_text())
    data["tree"]["src/test/groovy/demo/UnzipTest.groovy"] = data["tree"].pop("src/test/java/demo/UnzipTest.java")
    Path(os.environ["FAKE_VUL4J_DATA"]).write_text(json.dumps(data))
    cve = ds.get("VUL4J-99")
    cve.build["vul4j"]["test"] = "src/test/groovy"
    ws = ds.make_workspace(cve, cfg.root).prepare()
    assert not (ws.path / "src/test/groovy/demo/UnzipTest.groovy").exists()
    assert (ws.hidden / "pov" / "src/test/groovy/demo/UnzipTest.groovy").exists()
    r = run_cve(cve, ds, "oracle", cfg)
    assert r["status"] == "verified" and r["pov_ok"] is True, r


def test_remove_tree_ignores_files_that_vanish(tmp_path):
    # VUL4J-37: a background `git gc` deleted .git/objects/91 while the checkout's .git was being removed
    gone = tmp_path / "gone"
    vul4j_bench._ignore_missing(os.unlink, str(gone), (FileNotFoundError, FileNotFoundError(2, "gone"), None))
    with pytest.raises(PermissionError):
        vul4j_bench._ignore_missing(lambda p: (_ for _ in ()).throw(PermissionError(p)), str(tmp_path),
                                    (PermissionError, PermissionError(), None))
    d = tmp_path / "w" / ".git" / "objects" / "91"
    d.mkdir(parents=True)
    (d / "obj").write_text("x")
    vul4j_bench._remove_tree(tmp_path / "w" / ".git")
    assert not (tmp_path / "w" / ".git").exists()


def test_pov_class_name_with_wrong_case_is_found(bench):
    # VUL4J-44: the dataset says org.OWASP.esapi.codecs.CodecImmunityTest, the file is org/owasp/esapi/...
    ds, cfg, _ = bench
    cve = ds.get("VUL4J-99")
    cve.build["vul4j"]["failing_tests"] = "DEMO.UnzipTest#zipSlip[case 1]"
    ws = ds.make_workspace(cve, cfg.root).prepare()
    assert ws.info["pov_files"] == ["src/test/java/demo/UnzipTest.java"]
    assert not (ws.path / "src/test/java/demo/UnzipTest.java").exists()


def test_results_file_survives_a_power_cut(tmp_path):
    from graphpatch_v2.run_eval import append_row, load
    jl = tmp_path / "runs.jsonl"
    append_row(jl, {"mode": "oracle", "model": "", "slug": "VUL4J-1", "status": "verified"})
    with open(jl, "a", encoding="utf-8") as f:
        f.write('{"mode": "oracle", "slug": "VUL4J-2", "sta')        # PC turned off mid-write
    append_row(jl, {"mode": "oracle", "model": "", "slug": "VUL4J-3", "status": "verified"})
    assert sorted(r["slug"] for r in load(jl)) == ["VUL4J-1", "VUL4J-3"]


# ---- v3 enhancements, end to end

class _ScriptedLLM:
    model = "fake"

    def __init__(self, replies):
        self.replies = list(replies)
        self.roles = []
        self.prompts = []
        self.usage = type("U", (), {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0})()

    def chat(self, system, prompt, role="", json_mode=False):
        self.roles.append(role)
        self.prompts.append(prompt)
        self.usage.calls += 1
        return self.replies.pop(0)


def test_seeded_mode_accepts_the_rule_patch_without_a_model_call(bench):
    ds, cfg, _ = bench
    cfg.llm = _ScriptedLLM([])
    r = run_cve(ds.get("VUL4J-99"), ds, "seeded", cfg)
    assert r["status"] == "verified" and r["iterations"] == 1 and r["seeded"] is True, r
    assert cfg.llm.roles == []


def test_seeded_mode_hands_a_failing_rule_patch_to_the_agents(bench, monkeypatch):
    ds, cfg, _ = bench
    from graphpatch_v2 import pipeline
    # a rule patch that leaves the path open makes the model take over
    useless = ('FILE: src/main/java/demo/Unzip.java\n<<<<<<< SEARCH\n        out.close();\n=======\n'
               '        out.close(); // rule\n>>>>>>> REPLACE\n')
    monkeypatch.setattr(pipeline, "rule_patch", lambda *a: useless)
    good = ('FILE: src/main/java/demo/Unzip.java\n<<<<<<< SEARCH\n' + _first_sink_line(ds, cfg) + '\n=======\n'
            '        if (!file.getCanonicalPath().startsWith(dir.getCanonicalPath() + File.separator)) { throw new IOException("bad"); }\n'
            + _first_sink_line(ds, cfg) + '\n>>>>>>> REPLACE\n')
    critique = '{"root_cause": "No check.", "instructions": [{"file": "src/main/java/demo/Unzip.java", "method": "extract", "line": 10, "variable": "file", "action": "add a containment check"}]}'
    cfg.llm = _ScriptedLLM([critique, "plan", good])
    r = run_cve(ds.get("VUL4J-99"), ds, "seeded", cfg)
    assert cfg.llm.roles == ["critic", "planner", "coder"], cfg.llm.roles
    assert "RULE-BASED PATCH" in cfg.llm.prompts[2] and "Root cause: No check." in cfg.llm.prompts[2]
    assert r["iterations"] == 2 and r["critic_calls"] == 1 and "critic_invalid" not in r, r
    assert r["critic_path_coverage"] == [1.0]


def _first_sink_line(ds, cfg):
    ws = ds.make_workspace(ds.get("VUL4J-99"), cfg.root).prepare()
    text = (ws.path / "src/main/java/demo/Unzip.java").read_text()
    return next(l for l in text.split("\n") if "FileOutputStream" in l and "new" in l)


def _fake_codeql(monkeypatch):
    """CodeQL replaced by a rule on the source: the path is open unless a canonical-path check is present."""
    from graphpatch_v2 import codeql_oracle

    def alerts(self):
        text = (self.ws.path / "src/main/java/demo/Unzip.java").read_text()
        return set() if "getCanonicalPath" in text else {"java/path-injection::Unzip.java::new File"}
    monkeypatch.setattr(codeql_oracle.CodeQLOracle, "alerts", alerts)


def test_codeql_oracle_verifies_real_fix_and_fails_noop(bench, monkeypatch):
    ds, cfg, _ = bench
    _fake_codeql(monkeypatch)
    cfg.codeql = "fake-codeql"
    r = run_cve(ds.get("VUL4J-99"), ds, "oracle", cfg)
    assert r["status"] == "verified" and r["codeql_ok"] is True and r["codeql_paths_removed_by_real_fix"] == 1, r
    r = run_cve(ds.get("VUL4J-99"), ds, "noop", cfg)
    assert r["status"] == "plausible" and r["codeql_ok"] is False, r


def test_codeql_oracle_can_overrule_the_other_oracles(bench, monkeypatch):
    ds, cfg, _ = bench
    _fake_codeql(monkeypatch)
    cfg.codeql = "fake-codeql"
    # the rule's normalize().startsWith check satisfies javalang and the PoV test, but not this (fake) CodeQL
    r = run_cve(ds.get("VUL4J-99"), ds, "rule", cfg)
    assert r["graph_eval_ok"] is True and r["pov_ok"] is True and r["codeql_ok"] is False
    assert r["status"] == "plausible"


def test_codeql_failure_does_not_stop_the_run(bench, monkeypatch):
    ds, cfg, _ = bench
    from graphpatch_v2 import codeql_oracle

    def broken(self):
        raise RuntimeError("codeql database create failed")
    monkeypatch.setattr(codeql_oracle.CodeQLOracle, "alerts", broken)
    cfg.codeql = "fake-codeql"
    r = run_cve(ds.get("VUL4J-99"), ds, "oracle", cfg)
    assert r["status"] == "verified" and r["codeql_ok"] is None and "codeql_error" in r, r


def test_paper_mode_turns_the_enhancements_off(bench, monkeypatch):
    from graphpatch_v2 import taint
    ds, cfg, _ = bench
    cfg.structured_critic = cfg.fuzzy_edits = cfg.strict_guards = False
    free = "Root cause: no check. Add a canonical-path check in extract()."
    cfg.llm = _ScriptedLLM(["plan", 'FILE: src/main/java/demo/Unzip.java\n<<<<<<< SEARCH\nnothing like this\nat all here\n=======\nx\n>>>>>>> REPLACE\n', free,
                            'FILE: src/main/java/demo/Unzip.java\n<<<<<<< SEARCH\nstill nothing\nlike this\n=======\nx\n>>>>>>> REPLACE\n', free,
                            'FILE: src/main/java/demo/Unzip.java\n<<<<<<< SEARCH\nnope\nnope\n=======\nx\n>>>>>>> REPLACE\n'])
    r = run_cve(ds.get("VUL4J-99"), ds, "full", cfg)
    assert r["paper_mode"] is True and r["critic"] == "free" and "critic_calls" not in r, r
    assert free in cfg.llm.prompts[3]          # the Coder gets the Critic's text unchanged
    assert taint.STRICT_GUARDS is False
    taint.STRICT_GUARDS = True


def test_paper_mode_guard_rules():
    from graphpatch_v2 import taint
    import tempfile
    from pathlib import Path
    from graphpatch_v2.taint import TargetSpec, find_paths
    java = """import java.io.*; public class A { public void w(String name, File dir) throws IOException {
      if (name.equals("")) { throw new IOException(); }
      new FileOutputStream(new File(dir, name)); } }"""
    d = Path(tempfile.mkdtemp()); (d / "A.java").write_text(java)
    spec = TargetSpec("CWE-022", ["A.java"], {("A.java", "w", None)})
    assert len(find_paths(d, spec)) == 1            # v3: a check that restricts nothing does not clear the path
    taint.STRICT_GUARDS = False
    try:
        assert find_paths(d, spec) == []            # the paper's rule: any equals() check clears it
    finally:
        taint.STRICT_GUARDS = True


# ---- ml.py options, end to end

def test_fix_memory_feeds_the_planner_and_stores_the_verified_fix(bench, monkeypatch):
    pytest.importorskip("sklearn")
    from graphpatch_v2 import ml
    monkeypatch.setenv("GP_EMBED_MODEL", "tfidf")
    ds, cfg, _ = bench
    cfg.memory = cfg.root / "memory.jsonl"
    ml.FixMemory(cfg.memory).add("CVE-2000-1", "https://github.com/other/zip", "CWE-022",
                                 "ZipEntry entry getName new File dir FileOutputStream extract Unzip",
                                 "", "+ if (!f.getCanonicalPath().startsWith(base)) throw new IOException();")
    ml.FixMemory(cfg.memory).add("CVE-2099-0001", "https://github.com/demo/unzip", "CWE-022",
                                 "ZipEntry same project", "", "+ the answer itself")      # must never be shown
    good = ('FILE: src/main/java/demo/Unzip.java\n<<<<<<< SEARCH\n' + _first_sink_line(ds, cfg) + '\n=======\n'
            '        if (!file.getCanonicalPath().startsWith(dir.getCanonicalPath() + File.separator)) { throw new IOException("bad"); }\n'
            + _first_sink_line(ds, cfg) + '\n>>>>>>> REPLACE\n')
    cfg.llm = _ScriptedLLM(["plan", good])
    r = run_cve(ds.get("VUL4J-99"), ds, "full", cfg)
    assert r["status"] == "verified", r
    assert r["memory_hits"] == ["CVE-2000-1"] and r["memory_embedder"] == "tfidf", r
    assert "SIMILAR VERIFIED FIXES" in cfg.llm.prompts[0] and "the answer itself" not in cfg.llm.prompts[0]
    assert "SIMILAR VERIFIED FIXES" not in cfg.llm.prompts[1]          # only the Planner sees the examples
    stored = [json.loads(l) for l in cfg.memory.read_text().splitlines()]
    assert len(stored) == 2 and not r.get("memory_stored")                 # evaluation runs only read the memory


def test_memory_build_stores_training_fixes_and_retrieves_nothing(bench, monkeypatch):
    pytest.importorskip("sklearn")
    monkeypatch.setenv("GP_EMBED_MODEL", "tfidf")
    ds, cfg, _ = bench
    cfg.memory = cfg.root / "memory_build.jsonl"
    cfg.memory_build = True
    good = ('FILE: src/main/java/demo/Unzip.java\n<<<<<<< SEARCH\n' + _first_sink_line(ds, cfg) + '\n=======\n'
            '        if (!file.getCanonicalPath().startsWith(dir.getCanonicalPath() + File.separator)) { throw new IOException("bad"); }\n'
            + _first_sink_line(ds, cfg) + '\n>>>>>>> REPLACE\n')
    cfg.llm = _ScriptedLLM(["plan", good])
    r = run_cve(ds.get("VUL4J-99"), ds, "full", cfg)
    assert r["status"] == "verified" and r["memory_stored"] is True and "memory_hits" not in r, r
    stored = [json.loads(l) for l in cfg.memory.read_text().splitlines()]
    assert stored[-1]["cve"] == "CVE-2099-0001" and "getCanonicalPath" in stored[-1]["diff"]


def test_tfidf_log_option_adds_key_terms_for_the_critic(bench):
    pytest.importorskip("sklearn")
    ds, cfg, _ = bench
    cfg.tfidf_log = True
    cfg.max_iters = 2
    broken = ('FILE: src/main/java/demo/Unzip.java\n<<<<<<< SEARCH\n        out.close();\n=======\n'
              '        out.close(); // BREAK\n        if (!file.toPath().normalize().startsWith(dir.toPath())) throw new IOException();\n>>>>>>> REPLACE\n')
    critique = '{"root_cause": "A test broke.", "instructions": [{"file": "src/main/java/demo/Unzip.java", "method": "extract", "line": 10, "variable": "file", "action": "do not break the test"}]}'
    cfg.llm = _ScriptedLLM(["plan", broken, critique, broken])
    r = run_cve(ds.get("VUL4J-99"), ds, "full", cfg)
    assert cfg.llm.roles[:3] == ["planner", "coder", "critic"]
    assert "KEY TERMS IN THE LOG (TF-IDF" in cfg.llm.prompts[2] and r.get("tfidf_keywords"), r
