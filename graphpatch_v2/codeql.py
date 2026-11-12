"""CodeQL as a second, independent taint checker, and a calibration that counts how many
CWE-Bench-Java CVEs it makes judgeable.

A CVE is judgeable by a checker when the checker reports a path on the vulnerable commit
and the developers' real fix removes at least one of those paths. Today only the javalang
checker is used (15 of 120). This measures what CodeQL adds, with no language model and
no API key.

  python -m graphpatch_v2.codeql check   [--codeql PATH]
  python -m graphpatch_v2.codeql calibrate --dataset cwe-bench-java-master [--codeql PATH]
                                           [--cves ...] [--cwe CWE-079] [--skip-done]

CodeQL builds its database without compiling the project (--build-mode=none), so Maven or
Gradle and Docker are not needed. Results go to <root>/results/calibration_codeql.csv.

  python -m graphpatch_v2.codeql --benchmark vul4j calibrate [--cves VUL4J-41 ...] [--skip-done]

runs the same check on the judgeable Vul4J CVEs (benchmarks/vul4j_judgeable.txt) whose CWE CodeQL has
taint queries for; results go to <root>/results/calibration_codeql_vul4j.csv.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import shutil
import subprocess
import time
import traceback
from dataclasses import dataclass
from pathlib import Path

from .dataset import CVE, Dataset, ensure_dataset, is_test_path
from .workspace import _force_remove, final_fix_commit, git

SUITE = "codeql/java-queries:codeql-suites/java-security-extended.qls"
FIELDS = ["slug", "cve", "cwe", "targets", "buggy_paths", "fixed_paths", "detected", "cleared_by_fix",
          "reduced_by_fix", "fewer_after_fix", "rules", "status", "seconds"]


@dataclass(frozen=True)
class Alert:
    rule: str
    file: str          # repo-relative, forward slashes
    line: int          # sink line
    source_file: str
    source_line: int
    steps: tuple       # (file, line) of every location on the path, source first
    key: str           # survives line shifts: rule + files + the code text at source and sink


def find_codeql(explicit: str | None = None) -> str:
    # the bundle unpacked with `tar -xzf codeql-bundle-win64.tar.gz -C E:\` is found without $env:CODEQL
    for c in (explicit, os.environ.get("CODEQL"), shutil.which("codeql"), shutil.which("codeql.exe"),
              "E:\\codeql\\codeql.exe", "C:\\codeql\\codeql.exe"):
        if c and Path(c).exists():
            return str(c)
    raise FileNotFoundError("CodeQL not found: unpack the bundle to E:\\ (E:\\codeql\\codeql.exe), pass --codeql PATH or set $env:CODEQL")


# Set by calibrate() for the CVE being checked: every step of that CVE must end by this time (v2.19.10),
# and any process whose command line holds MARKER (the gp_runs folder) is ours to kill after a timeout.
DEADLINE: float | None = None
MARKER: str | None = None
HEARTBEAT = 300          # seconds between "still running" lines


def _kill_tree(p: subprocess.Popen) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(p.pid)], capture_output=True, timeout=120)
    else:
        import signal
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    kill_leftovers()


def kill_leftovers() -> None:
    """Kill java/codeql/git processes still working inside gp_runs. taskkill /T misses children whose parent
    already exited (codeql.exe can leave its Java running), and those kept CVE-2019-17573 and VUL4J-15 going."""
    if os.name != "nt" or not MARKER:
        return
    m = MARKER.replace("'", "''").lower()
    m2 = m.replace("\\", "/")
    ps = ("Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -ne $PID -and $_.CommandLine -and "
          f"($_.CommandLine.ToLower().Contains('{m}') -or $_.CommandLine.ToLower().Contains('{m2}')) -and $_.Name -match '^(java|codeql|git|git-remote-https)' }} | "
          "ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }")
    try:
        subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        pass


def _run(argv: list[str], timeout: int, cwd: Path | None = None) -> subprocess.CompletedProcess:
    """Run a command; after `timeout` seconds (or at the CVE's DEADLINE, whichever is first) kill it AND
    everything it started, then raise TimeoutExpired. Prints a line every few minutes so a slow step is visible.
    (codeql.exe starts Java and git starts git-remote-https; killing only the first process leaves the
    others holding the output pipes, and the wait never ends. That is how CVE-2019-17573 hung for hours.)"""
    start = time.time()
    limit = timeout if DEADLINE is None else min(timeout, DEADLINE - start)
    if limit <= 0:
        raise subprocess.TimeoutExpired(argv, timeout)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    kw = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP} if os.name == "nt" else {"start_new_session": True}
    p = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                         text=True, encoding="utf-8", errors="replace", **kw)
    try:
        while True:
            left = limit - (time.time() - start)
            if left <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            try:
                out, err = p.communicate(timeout=min(left, HEARTBEAT))
                break
            except subprocess.TimeoutExpired:
                if time.time() - start < limit:
                    print(f"      still running ({(time.time() - start) / 60:.0f} min, stops at {limit / 60:.0f} min)", flush=True)
    except BaseException:                   # timeout, or Ctrl+C: never leave CodeQL/Java running
        _kill_tree(p)
        try:
            p.communicate(timeout=60)
        except (subprocess.TimeoutExpired, ValueError):
            pass
        raise
    return subprocess.CompletedProcess(argv, p.returncode, out, err)


def _git(cwd: Path, *args, timeout: int = 1800) -> subprocess.CompletedProcess:
    return _run(["git", *args], timeout, cwd)


# ------------------------------------------------------------ SARIF -> alerts

def _loc(pl: dict, src: Path | None = None) -> tuple[str, int]:
    uri = (pl.get("artifactLocation") or {}).get("uri", "").replace("\\", "/")
    if uri.startswith("file:") and src is not None:      # absolute URI: make it relative to the source tree
        from urllib.parse import unquote, urlparse
        path = unquote(urlparse(uri).path).lstrip("/")
        root = str(src.resolve()).replace("\\", "/").lstrip("/")
        uri = path[len(root):].lstrip("/") if path.lower().startswith(root.lower()) else path
    while uri.startswith("./"):
        uri = uri[2:]
    return uri, int((pl.get("region") or {}).get("startLine") or 0)


def _code(src: Path | None, file: str, line: int) -> str:
    if src is None or not line:
        return ""
    try:
        lines = (src / file).read_text(encoding="utf-8", errors="replace").splitlines()
        return " ".join(lines[line - 1].split()) if 0 < line <= len(lines) else ""
    except OSError:
        return ""


def _rules(run: dict) -> list[dict]:
    rules = list((run.get("tool") or {}).get("driver", {}).get("rules") or [])
    for ext in (run.get("tool") or {}).get("extensions") or []:
        rules += ext.get("rules") or []
    return rules


def _rule_cwes(rule: dict) -> set[str]:
    out = set()
    for t in (rule.get("properties") or {}).get("tags") or []:
        if t.lower().startswith("external/cwe/cwe-"):
            out.add("CWE-" + t.rsplit("-", 1)[1].zfill(3))
    return out


# CodeQL files some queries under a related CWE: OGNL/SpEL/template injection are CWE-917/1336, not CWE-094;
# argument injection is CWE-088. A CVE's CWE accepts the queries of its whole family.
CWE_FAMILY = {
    "CWE-022": {"CWE-022", "CWE-023", "CWE-036", "CWE-073"},
    "CWE-078": {"CWE-078", "CWE-077", "CWE-088"},
    "CWE-079": {"CWE-079", "CWE-080"},
    "CWE-094": {"CWE-094", "CWE-095", "CWE-917", "CWE-1336"},
    # Vul4J CWEs (v2.19.9)
    "CWE-077": {"CWE-078", "CWE-077", "CWE-088"},
    "CWE-611": {"CWE-611", "CWE-776", "CWE-827"},
    "CWE-502": {"CWE-502"},
    "CWE-918": {"CWE-918"},
    # CWE-74 is "injection" in general: any of the injection families
    "CWE-074": {"CWE-074", "CWE-077", "CWE-078", "CWE-079", "CWE-088", "CWE-089", "CWE-090", "CWE-094",
                "CWE-113", "CWE-643", "CWE-917", "CWE-1336"},
}
# Vul4J CWEs CodeQL has taint-path queries for; the other Vul4J CWEs (CWE-20, 835, 264, ...) are not run
VUL4J_TAINT_CWES = ("CWE-022", "CWE-074", "CWE-077", "CWE-078", "CWE-079", "CWE-502", "CWE-611", "CWE-918")


def parse_sarif(sarif: dict, cwe: str, src: Path | None = None, files: list[str] | None = None) -> list[Alert]:
    """Taint-path alerts for one CWE. With `files`, keep only paths that touch one of them
    (the files the real fix changed), the same localisation the javalang checker gets."""
    want = set(files or [])
    out: dict[str, Alert] = {}
    for run in sarif.get("runs") or []:
        by_id = {r.get("id"): r for r in _rules(run)}
        for res in run.get("results") or []:
            rule = by_id.get(res.get("ruleId")) or {}
            props = rule.get("properties") or {}
            if props.get("kind") not in (None, "path-problem") or not (CWE_FAMILY.get(cwe, {cwe}) & _rule_cwes(rule)):
                continue
            if not res.get("locations"):
                continue
            sink = _loc(res["locations"][0].get("physicalLocation") or {}, src)
            steps = []
            for flow in res.get("codeFlows") or []:
                for tf in flow.get("threadFlows") or []:
                    steps = [_loc((l.get("location") or {}).get("physicalLocation") or {}, src) for l in tf.get("locations") or []]
                    break
                break
            if not steps:
                steps = [sink]
            if want and not ({f for f, _ in steps} | {sink[0]}) & want:
                continue
            source = steps[0]
            key = f"{res.get('ruleId')}::{source[0]}::{_code(src, *source)}::{sink[0]}::{_code(src, *sink)}"
            out.setdefault(key, Alert(res.get("ruleId", ""), sink[0], sink[1], source[0], source[1], tuple(steps), key))
    return list(out.values())


# ------------------------------------------------------------ running CodeQL

def analyze(codeql: str, src: Path, work: Path, timeout: int = 7200) -> dict:
    """Build a database from the source tree (no compile) and run the Java security suite."""
    db, out = work / "db", work / "codeql.sarif"
    shutil.rmtree(db, ignore_errors=True)
    r = _run([codeql, "database", "create", str(db), "--language=java", "--build-mode=none",
              f"--source-root={src}", "--overwrite", "--threads=0"], timeout)
    if r.returncode != 0:
        raise RuntimeError("codeql database create failed: " + (r.stderr or r.stdout)[-600:])
    r = _run([codeql, "database", "analyze", str(db), SUITE, "--format=sarif-latest", f"--output={out}",
              "--threads=0", "--no-print-diagnostics-summary"], timeout)
    if r.returncode != 0:
        raise RuntimeError("codeql database analyze failed: " + (r.stderr or r.stdout)[-600:])
    shutil.rmtree(db, ignore_errors=True)   # databases are large; the SARIF is all we keep
    return json.loads(out.read_text(encoding="utf-8"))


def _cache(root: Path, cve: CVE, timeout: int = 1800) -> Path:
    """A blob-less clone of the project, shared by every CVE of that project."""
    cache = Path(root) / "cache" / cve.repo_url.rstrip("/").split("github.com/")[-1].replace("/", "__")
    if not (cache / ".git").exists() and not (cache / "HEAD").exists():
        cache.parent.mkdir(parents=True, exist_ok=True)
        print(f"    cloning {cve.repo_url} ...", flush=True)
        # the vul4j repository has a branch per vulnerability: take only main, then fetch each CVE's branch
        one = ["--single-branch"] if cve.repo_url == VUL4J_REPO else []
        r = _git(cache.parent, "clone", "-c", "core.autocrlf=false", "--filter=blob:none", "--no-checkout", *one,
                 cve.repo_url, str(cache), timeout=2 * timeout)
        if r.returncode != 0:
            raise RuntimeError("git clone failed: " + r.stderr[-300:])
    return cache


VUL4J_FIX_FILES = Path(__file__).parent / "benchmarks" / "vul4j_fix_files.json"


VUL4J_REPO = "https://github.com/tuhh-softsec/vul4j"
VUL4J_SOURCE = "vul4j-branch"     # rows made from Vul4J's own copy of the code (v2.19.11)


def vul4j_prepare(root: Path, cve: CVE, timeout: int = 1800) -> None:
    """Use the same code `vul4j checkout` uses: the vul4j repository keeps one branch per vulnerability
    (VUL4J-23, ...) whose head is the vulnerable code. The fixed code is that tree with the human patch's
    files taken from the fix commit, as `vul4j checkout` builds its human_patch commit. The fix's files are
    the main-source files the human patch changed (from the oracle run's diffs, else from git).
    Old upstream commits are not always on GitHub any more (Apache Sling moved), which is why the
    project's own repository is only a fallback."""
    if cve.buggy_commit != "vulnerable":
        return
    fix = cve.fix_commits[0]
    known = json.loads(VUL4J_FIX_FILES.read_text(encoding="utf-8")) if VUL4J_FIX_FILES.exists() else {}
    project_url = cve.repo_url
    cve.repo_url = VUL4J_REPO
    cache = _cache(root, cve, timeout)
    branch = f"refs/remotes/origin/{cve.slug}"
    if git(cache, "rev-parse", "-q", "--verify", branch, check=False).returncode != 0:
        print(f"    fetching Vul4J's copy of {cve.slug} ...", flush=True)
        _git(cache, "fetch", "--filter=blob:none", "origin", f"+refs/heads/{cve.slug}:{branch}", timeout=2 * timeout)
    r = git(cache, "rev-parse", "-q", "--verify", branch, check=False)
    if r.returncode == 0 and git(cache, "cat-file", "-e", f"{fix}^{{commit}}", check=False).returncode == 0:
        cve.buggy_commit = r.stdout.strip()
        cve.build = {**(cve.build or {}), "codeql_fixed_overlay": True, "codeql_source": VUL4J_SOURCE}
    else:                                   # no Vul4J branch: the parent of the fix in the project's repository
        cve.repo_url = project_url
        cache = _cache(root, cve, timeout)
        if git(cache, "cat-file", "-e", f"{fix}^{{commit}}", check=False).returncode != 0:
            _git(cache, "fetch", "--filter=blob:none", "origin", fix, timeout=timeout)
        r = git(cache, "rev-parse", f"{fix}^1", check=False)
        if r.returncode != 0:
            raise RuntimeError(f"cannot find fix commit {fix[:10]} in Vul4J's copy or in {project_url}")
        cve.buggy_commit = r.stdout.strip()
        cve.build = {**(cve.build or {}), "codeql_source": "project-parent"}
    files = known.get(cve.slug) or []
    if not files:
        d = git(cache, "diff", "--name-only", cve.buggy_commit, fix, check=False)
        files = [f for f in d.stdout.splitlines() if f.endswith(".java") and not is_test_path(f)]
    cve.fix_rows = [{"file": f, "method": "", "class": Path(f).stem, "signature": ""} for f in files]


def full_tree(root: Path, cve: CVE, commit: str, dest: Path, timeout: int = 1800) -> Path:
    """A full checkout of the project at `commit` (CodeQL needs the whole tree to resolve types)."""
    cache = _cache(root, cve, timeout)
    if git(cache, "cat-file", "-e", f"{commit}^{{commit}}", check=False).returncode != 0:
        _git(cache, "fetch", "--filter=blob:none", "origin", commit, timeout=timeout)
    remove_tree(cache, dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"    checking out {commit[:10]} ...", flush=True)
    r = _git(cache, "worktree", "add", "-f", "--detach", str(dest), commit, timeout=timeout)
    if r.returncode != 0:
        raise RuntimeError("git worktree add failed: " + r.stderr[-300:])
    return dest


def remove_tree(cache: Path, dest: Path):
    if dest.exists():
        git(cache, "worktree", "remove", "-f", str(dest), check=False)
    if dest.exists():                       # git could not remove it (not a worktree, or files locked)
        shutil.rmtree(dest, onerror=_force_remove)
    git(cache, "worktree", "prune", check=False)


def calibrate_one(codeql: str, cve: CVE, root: Path, keep: bool = False, timeout: int = 7200) -> dict:
    vul4j_prepare(root, cve, timeout)
    row = {"slug": cve.slug, "cve": cve.cve_id, "cwe": cve.cwe, "targets": len(cve.target_files)}
    if (cve.build or {}).get("codeql_source"):
        row["source"] = cve.build["codeql_source"]
    if not cve.target_files:
        row["status"] = "no main-source target files in fix_info"
        return row
    cache = _cache(root, cve, timeout)
    base = Path(root) / "codeql" / cve.slug
    keys = {}
    for label in ("buggy", "fixed"):
        commit = cve.buggy_commit
        if label == "fixed":
            if not keys["buggy"]:          # nothing on the vulnerable code: the fix cannot remove anything
                row["fixed_paths"] = None
                break
            commit = final_fix_commit(cache, cve)
            row["fix_commit"] = commit
        overlay = label == "fixed" and (cve.build or {}).get("codeql_fixed_overlay")
        src = full_tree(root, cve, cve.buggy_commit if overlay else commit, base / label / "src", timeout)
        if overlay:                         # vulnerable tree + the human patch's files, as `vul4j checkout` does
            r = _git(src, "checkout", commit, "--", *cve.target_files, timeout=timeout)
            if r.returncode != 0:
                raise RuntimeError("applying the human patch files failed: " + r.stderr[-300:])
        try:
            print(f"    CodeQL on the {label} code ...", flush=True)
            sarif = analyze(codeql, src, base / label, timeout)
            alerts = parse_sarif(sarif, cve.cwe, src, cve.target_files)
        finally:
            if not keep:
                remove_tree(cache, src)
        keys[label] = {a.key for a in alerts}
        row[f"{label}_paths"] = len(alerts)
        row[f"{label}_keys"] = sorted(keys[label])
        if label == "buggy":
            row["rules"] = " ".join(sorted({a.rule for a in alerts}))
    row["detected"] = bool(keys["buggy"])
    fixed = keys.get("fixed", set())
    row["cleared_by_fix"] = row["detected"] and not fixed
    row["reduced_by_fix"] = row["detected"] and len(keys["buggy"] - fixed) > 0
    # stricter view for the paper: the fix leaves fewer alerts (a reworded sink line alone does not count)
    row["fewer_after_fix"] = row["detected"] and len(fixed) < len(keys["buggy"])
    row["status"] = "ok"
    return row


def _done(path: Path) -> dict[str, dict]:
    done = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                r = json.loads(line)
                if r.get("status") == "ok" or str(r.get("status", "")).startswith(("no main-source", "timeout", "skipped")):
                    done[r["slug"]] = r
    return done


def calibrate(codeql: str, cves: list[CVE], root: Path, skip_done: bool = False, keep: bool = False,
              timeout: int = 7200, exclude: list[str] | None = None, name: str = "calibration_codeql",
              cve_timeout: int | None = None) -> list[dict]:
    global DEADLINE, MARKER
    cve_timeout = cve_timeout or 2 * timeout
    out = Path(root) / "results" / f"{name}.csv"
    log = out.with_suffix(".jsonl")
    out.parent.mkdir(parents=True, exist_ok=True)
    done = _done(log) if skip_done else {}
    # Vul4J rows made before v2.19.11 used the parent commit; redo them (timeouts and hand skips stay)
    done = {k: v for k, v in done.items() if not k.startswith("VUL4J-") or v.get("source") in (VUL4J_SOURCE, "project-parent")
            or str(v.get("status", "")).startswith(("timeout", "skipped"))}
    if not skip_done:
        log.unlink(missing_ok=True)
    rows = []
    MARKER = str(Path(root).resolve())
    kill_leftovers()                        # from an earlier run that was stopped by hand
    for i, c in enumerate(cves, 1):
        if c.slug in done:
            rows.append(done[c.slug])
            print(f"[{i}/{len(cves)}] {c.cve_id} already done", flush=True)
            continue
        t = time.time()
        if c.cve_id in (exclude or []) or c.slug in (exclude or []):
            r = {"slug": c.slug, "cve": c.cve_id, "cwe": c.cwe, "status": "skipped: excluded by hand (too slow on this PC)"}
        else:
            DEADLINE = time.time() + cve_timeout
            try:
                r = calibrate_one(codeql, c, root, keep, timeout)
            except subprocess.TimeoutExpired:
                # very large projects (e.g. Apache CXF): recorded, so --skip-done does not retry them every time
                r = {"slug": c.slug, "cve": c.cve_id, "cwe": c.cwe,
                     "status": f"timeout: a step took over {timeout}s or the CVE over {cve_timeout}s"}
            except Exception as e:
                r = {"slug": c.slug, "cve": c.cve_id, "cwe": c.cwe, "status": f"error: {e}"[:300]}
                traceback.print_exc()
            finally:
                DEADLINE = None
        r["seconds"] = round(time.time() - t, 1)
        rows.append(r)
        print(f"[{i}/{len(cves)}] {c.cve_id} {c.cwe} buggy={r.get('buggy_paths')} fixed={r.get('fixed_paths')} "
              f"{r['status'][:60]} ({r['seconds']}s)", flush=True)
        with open(log, "a", encoding="utf-8") as f:
            f.write(json.dumps(r) + "\n")
    # the CSV holds every CVE in the log, not only this run's selection (runs with --cwe used to overwrite it)
    latest = {}
    for line in log.read_text(encoding="utf-8").splitlines() if log.exists() else []:
        if line.strip():
            r = json.loads(line)
            latest[r["slug"]] = r
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(latest.values() or rows)
    return rows


# ------------------------------------------------------------ report

def _truthy(v) -> bool:
    return v is True or str(v).strip().lower() == "true"


def combine(codeql_rows: list[dict], javalang_rows: list[dict]) -> dict:
    """Per CWE: CVEs judgeable by javalang, by CodeQL, and by either."""
    jl = {r["slug"]: _truthy(r.get("reduced_by_fix")) for r in javalang_rows}
    cq = {r["slug"]: _truthy(r.get("reduced_by_fix")) for r in codeql_rows if r.get("status") == "ok"}
    cwe = {r["slug"]: r["cwe"] for r in javalang_rows + codeql_rows}
    table: dict[str, dict] = {}
    for slug in sorted(set(jl) | set(cq)):
        t = table.setdefault(cwe[slug], {"cves": 0, "javalang": 0, "codeql": 0, "codeql_only": 0, "either": 0, "codeql_checked": 0})
        t["cves"] += 1
        t["codeql_checked"] += slug in cq
        a, b = jl.get(slug, False), cq.get(slug, False)
        t["javalang"] += a
        t["codeql"] += b
        t["codeql_only"] += b and not a
        t["either"] += a or b
    return table


def _ids(path: Path) -> list[str]:
    return [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]


def print_report(table: dict, name: str = "calibration_codeql"):
    print(f"\n{'CWE':8} {'CVEs':>5} {'CodeQL run':>10} {'javalang':>9} {'CodeQL':>7} {'new':>4} {'either':>7}")
    tot = {k: 0 for k in ("cves", "codeql_checked", "javalang", "codeql", "codeql_only", "either")}
    for c, t in sorted(table.items()):
        print(f"{c:8} {t['cves']:>5} {t['codeql_checked']:>10} {t['javalang']:>9} {t['codeql']:>7} {t['codeql_only']:>4} {t['either']:>7}")
        for k in tot:
            tot[k] += t[k]
    print(f"{'total':8} {tot['cves']:>5} {tot['codeql_checked']:>10} {tot['javalang']:>9} {tot['codeql']:>7} {tot['codeql_only']:>4} {tot['either']:>7}")
    print("\njudgeable = the checker finds a path on the vulnerable code and the real fix removes one.")
    print(f"'new' = judgeable by CodeQL but not by javalang. Send {name}.csv to Claude.")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="graphpatch_v2.codeql")
    ap.add_argument("--root", default="gp_runs")
    ap.add_argument("--dataset", default=None)
    ap.add_argument("--benchmark", choices=["cwe-bench", "vul4j"], default="cwe-bench",
                    help="vul4j: the Vul4J CVEs whose developer fix our harness verifies, taint CWEs only")
    ap.add_argument("--codeql", default=None, help="path to codeql.exe (or set $env:CODEQL)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("check", help="check that CodeQL and its Java queries are installed")
    c = sub.add_parser("calibrate", help="count CVEs CodeQL makes judgeable")
    c.add_argument("--cves", nargs="*")
    c.add_argument("--cwe")
    c.add_argument("--limit", type=int)
    c.add_argument("--skip-done", action="store_true", help="continue an interrupted calibration")
    c.add_argument("--keep", action="store_true", help="keep the checked-out source trees")
    c.add_argument("--exclude", nargs="*", default=[], help="CVE ids to skip; recorded as 'skipped' (e.g. too slow on this PC)")
    c.add_argument("--timeout", type=int, default=1800,
                   help="seconds allowed per CodeQL step (database create, analyze); slower CVEs are recorded as timeout")
    c.add_argument("--cve-timeout", type=int, default=None,
                   help="seconds allowed for one CVE in total (clone, checkouts, CodeQL); default 2 x --timeout")
    sub.add_parser("report", help="print the table again from the saved CSVs")
    j = sub.add_parser("judgeable", help="print the CVEs CodeQL can judge (for run_eval --cves-file with --codeql-oracle)")
    j.add_argument("--only-new", action="store_true", help="only those javalang cannot judge")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve()

    if a.cmd == "check":
        codeql = find_codeql(a.codeql)
        v = _run([codeql, "version", "--format=terse"], 120)
        q = _run([codeql, "resolve", "queries", SUITE], 600)
        n = len([l for l in q.stdout.splitlines() if l.strip().endswith(".ql")])
        print(f"CodeQL {v.stdout.strip() or '?'} at {codeql}")
        print(f"Java security queries found: {n}" if q.returncode == 0 and n else
              "Java queries NOT found: download the CodeQL *bundle* (codeql-bundle-win64.tar.gz), not the bare CLI")
        raise SystemExit(0 if q.returncode == 0 and n else 1)

    name = "calibration_codeql" if a.benchmark == "cwe-bench" else "calibration_codeql_vul4j"
    if a.benchmark == "vul4j":
        from .vul4j_bench import Vul4JDataset
        bench = Path(__file__).parent / "benchmarks"
        judgeable = _ids(bench / "vul4j_judgeable.txt")
        graph_set = set(_ids(bench / "vul4j_graph_set.txt"))
        ds = Vul4JDataset()
        picked = getattr(a, "cves", None)
        cves = ds.select(picked) if picked else [c for c in ds.select(None) if c.slug in judgeable and c.cwe in VUL4J_TAINT_CWES]
        want_cwe, limit = getattr(a, "cwe", None), getattr(a, "limit", None)
        cves = [c for c in cves if not want_cwe or c.cwe == want_cwe][:limit or None]
        # javalang: the 4 CVEs where the developers' fix removes a javalang path (oracle run, 2026-10-18)
        # (the table always covers the whole selection, also when --cves runs only a few)
        every = [c for c in ds.select(None) if c.slug in judgeable and c.cwe in VUL4J_TAINT_CWES]
        jl_rows = [{"slug": c.slug, "cwe": c.cwe, "reduced_by_fix": c.slug in graph_set} for c in every]
    else:
        javalang_csv = root / "results" / "calibration.csv"
        if not javalang_csv.exists():
            javalang_csv = Path(__file__).parent / "sample_results" / "calibration.csv"
        jl_rows = list(csv.DictReader(open(javalang_csv, encoding="utf-8")))

    if a.cmd == "judgeable":
        rows = list(_done(root / "results" / f"{name}.jsonl").values())
        jl = {r["slug"] for r in jl_rows if _truthy(r.get("reduced_by_fix"))}
        for r in sorted(rows, key=lambda r: (r.get("cwe") or "", r.get("cve") or "")):
            if r.get("status") == "ok" and _truthy(r.get("reduced_by_fix")) and not (a.only_new and r["slug"] in jl):
                print(f"{r.get('cve') or r['slug']}  # {r.get('cwe')}{'' if r['slug'] in jl else ', CodeQL only'}")
        return

    if a.cmd == "calibrate":
        codeql = find_codeql(a.codeql)
        if a.benchmark == "cwe-bench":
            cves = ensure_dataset(Path(a.dataset) if a.dataset else root / "cwe-bench-java").select(a.cves, a.cwe, a.limit)
        calibrate(codeql, cves, root, a.skip_done, a.keep, a.timeout, a.exclude, name, a.cve_timeout)
    rows = list(_done(root / "results" / f"{name}.jsonl").values())   # the table covers every CVE run so far
    print_report(combine(rows, jl_rows), name)


if __name__ == "__main__":
    try:
        main()
    except FileNotFoundError as e:
        raise SystemExit(f"error: {e}")
