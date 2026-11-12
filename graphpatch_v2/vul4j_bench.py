"""Vul4J as a second benchmark (https://github.com/tuhh-softsec/vul4j, dataset CC-BY-4.0).

Vul4J has 79 real Java vulnerabilities, each with proof-of-vulnerability (PoV) tests written by the
developers: they fail on the vulnerable code and pass on the human fix. That gives an oracle that does
not depend on our own taint checker.

Everything runs inside the Vul4J Docker image (tuhhsoftsec/vul4j), which has the right JDKs, Maven and
Gradle caches and the `vul4j` command; see vul4j_run.ps1. Compared with CWE-Bench-Java:

* workspace  `vul4j checkout`, then the human patch files and the PoV test classes are moved out of
             the tree and the git history is replaced by one baseline commit, so no model ever sees them
* build      `vul4j compile` (the dataset's own compile command)
* tests      `vul4j test -b all`, compared with a baseline run on the unpatched code (PoV tests hidden)
* PoV        the hidden PoV test classes are put back and `vul4j test -b povs` must pass, as in
             `vul4j evaluate`. It also runs for patches that broke other tests, so the Vul4J protocol
             (compile + PoV only) can be reported next to our stricter verdict
* graph      the javalang checker where it has rules (path traversal, command injection, XSS, code
             injection); for other CWEs no path is found and "full" gets no graph feedback

Localisation: the files the human patch changed (file level), as `vul4j` itself extracts them.
"""

from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from .build import StepResult, _tail
from .dataset import CVE
from .validator import Validator, Verdict, run_codeql
from .workspace import BASE_BRANCH, Workspace, _force_remove, git

DATA = Path(__file__).parent / "benchmarks" / "vul4j_dataset.csv"
VUL4J_DIR = "VUL4J"            # vul4j's own folder inside a checkout (vulnerability_info.json, logs, results)
# PoV test classes are not always Java: VUL4J-22 (Shiro) has a Groovy test under src/test/groovy
TEST_EXTS = (".java", ".groovy", ".kt", ".scala")
IGNORED = [f"{VUL4J_DIR}/", "target/", "build/", ".gradle/", ".graphpatch/"]


def _ignore_missing(func, path, exc_info):
    if not isinstance(exc_info[1], FileNotFoundError):   # already gone: nothing to do
        _force_remove(func, path, exc_info)


def _remove_tree(path: Path) -> None:
    """Delete a checkout or its .git. `vul4j checkout` makes commits, and git can start a background
    `git gc --auto` that deletes object folders while we delete them too (VUL4J-37 failed this way),
    so wait for a running gc, ignore files that vanish, and retry a few times."""
    gc_pid = (path if path.name == ".git" else path / ".git") / "gc.pid"
    for _ in range(120):
        if not gc_pid.exists():
            break
        time.sleep(1)
    for attempt in range(5):
        try:
            shutil.rmtree(path, onerror=_ignore_missing)
        except OSError:
            if attempt == 4:
                raise
        if not path.exists():
            return
        time.sleep(2)
    if path.exists():
        raise RuntimeError(f"could not delete {path}")


def vul4j_cmd() -> list[str]:
    return (os.environ.get("GP_VUL4J_CMD") or "vul4j").split()


def norm_cwe(raw: str) -> str:
    m = re.match(r"CWE-(\d+)$", (raw or "").strip())
    return f"CWE-{int(m.group(1)):03d}" if m else "CWE-NONE"


def pov_tests(row: dict) -> list[str]:
    """`Class#method` names of the PoV tests."""
    return [t.strip() for t in (row.get("failing_tests") or "").split(",") if t.strip()]


class Vul4JDataset:
    name = "vul4j"

    def __init__(self, csv_path: Path | None = None):
        self.root = Path(csv_path or DATA)
        self.cves: dict[str, CVE] = {}
        for r in csv.DictReader(open(self.root, encoding="utf-8")):
            vid = r["vul_id"].strip()
            if vid.endswith("-S") or not pov_tests(r):   # SpotBugs-only entries have no PoV test
                continue
            cve_id = (r.get("cve_id") or "").strip()
            cve_id = cve_id if cve_id.upper().startswith("CVE-") else vid
            self.cves[vid] = CVE(
                slug=vid, cve_id=cve_id, cwe=norm_cwe(r.get("cwe_id")), cwe_name=(r.get("cwe_name") or "").strip(),
                repo_url=f"https://github.com/{r['repo_slug'].strip()}", buggy_commit="vulnerable",
                fix_commits=[r["human_patch"].rstrip("/").split("/")[-1]],
                advisory={"summary": f"{cve_id}: {(r.get('cwe_name') or '').strip()}", "details": ""},
                build={"jdk_version": r.get("compliance_level", ""), "vul4j": r},
                fix_rows=[],   # filled from the checkout (the files the human patch changed)
            )

    def get(self, key: str) -> CVE:
        k = key.strip().upper()
        if k in self.cves:
            return self.cves[k]
        if k.isdigit() and f"VUL4J-{k}" in self.cves:
            return self.cves[f"VUL4J-{k}"]
        matches = [c for c in self.cves.values() if c.cve_id.upper() == k]
        if not matches:
            raise KeyError(f"{key} is not a Vul4J PoV entry")
        return matches[0]

    def select(self, keys: list[str] | None = None, cwe: str | None = None, limit: int | None = None) -> list[CVE]:
        out = [self.get(k) for k in keys] if keys else list(self.cves.values())
        if cwe:
            out = [c for c in out if c.cwe == cwe]
        return out[:limit] if limit else out

    def build_patch(self, cve: CVE) -> Path | None:
        return None

    # hooks used by pipeline.run_cve
    def make_workspace(self, cve: CVE, root: Path) -> "Vul4JWorkspace":
        return Vul4JWorkspace(cve, self, root)

    def make_builder(self, ws: "Vul4JWorkspace", cfg) -> "Vul4JBuilder":
        return Vul4JBuilder(ws, build_timeout=cfg.build_timeout, test_timeout=cfg.test_timeout,
                            tests="skip" if cfg.tests == "skip" else "all")

    def make_validator(self, ws, spec, builder, before, require_tests=True) -> "Vul4JValidator":
        return Vul4JValidator(ws, spec, builder, before, require_tests)


def _run(argv: list[str], cwd: Path | None, timeout: int) -> tuple[int | None, str, float]:
    t = time.time()
    try:
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return p.returncode, (p.stdout or "") + "\n" + (p.stderr or ""), time.time() - t
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode(errors="replace") if isinstance(e.stdout, bytes) else (e.stdout or "")
        return None, out, time.time() - t
    except FileNotFoundError as e:
        return 127, str(e), time.time() - t


class Vul4JWorkspace(Workspace):
    def __init__(self, cve: CVE, dataset: Vul4JDataset, root: Path):
        self.cve = cve
        self.dataset = dataset
        self.path = Path(root).resolve() / "vul4j" / "work" / cve.slug
        self.hidden = Path(root).resolve() / "vul4j" / "hidden" / cve.slug   # never inside the tree a model sees
        self.cache = self.path
        self.base = f"{BASE_BRANCH}-{cve.slug}"
        self.info: dict = {}

    def _load(self):
        self.info = json.loads((self.hidden / "ready.json").read_text(encoding="utf-8"))
        self.cve.fix_rows = [{"file": f, "method": "", "class": Path(f).stem, "signature": ""} for f in self.info["targets"]]

    def prepare(self) -> "Vul4JWorkspace":
        ready = self.hidden / "ready.json"
        if ready.exists() and self.path.exists() and git(self.path, "rev-parse", "--verify", self.base, check=False).returncode == 0:
            self._load()
            self.reset()
            return self
        for d in (self.path, self.hidden):
            if d.exists():
                _remove_tree(d)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.hidden.mkdir(parents=True)
        rc, log, _ = _run([*vul4j_cmd(), "checkout", "--id", self.cve.slug, "-d", str(self.path)], None, 3600)
        if rc != 0 or not (self.path / VUL4J_DIR / "vulnerability_info.json").exists():
            raise RuntimeError(f"vul4j checkout failed: {_tail(log, 15)}")

        # 1. the human patch: vul4j keeps a copy of the fixed files inside the tree; move it out
        patch_dir = self.path / VUL4J_DIR / "human_patch"
        paths = json.loads((patch_dir / "paths.json").read_text(encoding="utf-8"))
        targets = sorted(set(paths.values()))
        shutil.move(str(patch_dir), str(self.hidden / "human_patch"))
        vgit = Path(os.environ.get("VUL4J_GIT", "/vul4j"))
        bench = vgit / "benchmark_patches" / self.cve.slug / "human_patch.patch"
        if bench.exists():   # compatibility overlay vul4j applies together with the human patch
            shutil.copy(bench, self.hidden / "human_patch.patch")

        # 2. the PoV test classes: the vulnerable version already contains them (from the fix commit)
        row = self.cve.build["vul4j"]
        pov_files = self._find_pov_files(row)
        if not pov_files:
            raise RuntimeError("could not find the PoV test files in the checkout: " + ", ".join(pov_tests(row)))
        for f in pov_files:
            dest = self.hidden / "pov" / f
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(self.path / f), str(dest))

        # 3. a fresh history: vul4j's own repo has a "human_patch" commit
        _remove_tree(self.path / ".git")
        git(self.path, "init", "-q")
        git(self.path, "config", "core.autocrlf", "false")
        (self.path / ".git" / "info").mkdir(parents=True, exist_ok=True)
        with open(self.path / ".git" / "info" / "exclude", "a", encoding="utf-8") as f:
            f.write("\n".join(IGNORED) + "\n")
        git(self.path, "checkout", "-q", "-B", self.base)
        git(self.path, "add", "-A")
        git(self.path, "-c", "user.name=graphpatch", "-c", "user.email=graphpatch@localhost",
            "commit", "-q", "--allow-empty", "-m", "graphpatch baseline (Vul4J vulnerable version, PoV tests hidden)")
        ready.write_text(json.dumps({"targets": targets, "patch_paths": paths, "pov_files": pov_files,
                                     "pov_tests": pov_tests(row)}, indent=2), encoding="utf-8")
        self._load()
        return self

    def _find_pov_files(self, row: dict) -> list[str]:
        module = (row.get("failing_module") or "").strip()
        test_dir = (row.get("test") or "src/test/java").strip().strip("/")
        found = []
        for cls in sorted({t.split("#")[0] for t in pov_tests(row)}):
            rel = cls.split("$")[0].replace(".", "/")
            base = f"{module}/{test_dir}/{rel}" if module and module != "root" else f"{test_dir}/{rel}"
            hit = next((base + ext for ext in TEST_EXTS if (self.path / (base + ext)).exists()), None)
            if hit is None:   # some entries name the module differently: search the tree
                matches = [p for ext in TEST_EXTS for p in self.path.rglob(f"{Path(rel).name}{ext}")
                           if p.as_posix().endswith(f"/{rel}{ext}") and VUL4J_DIR not in p.relative_to(self.path).parts]
                if not matches:   # VUL4J-44 lists its PoV as org.OWASP.esapi..., the package is org.owasp.esapi
                    want = rel.lower()
                    matches = [p for p in self.path.rglob("*") if p.suffix in TEST_EXTS and p.is_file()
                               and p.as_posix().lower().endswith(f"/{want}{p.suffix}")
                               and VUL4J_DIR not in p.relative_to(self.path).parts]
                hit = matches[0].relative_to(self.path).as_posix() if len(matches) == 1 else None
            if hit and hit not in found:
                found.append(hit)
        return found

    # ------------------------------------------------------------ hidden material, used only by the oracles

    def restore_pov(self) -> list[str]:
        for f in self.info["pov_files"]:
            dest = self.path / f
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(self.hidden / "pov" / f, dest)
        return list(self.info["pov_files"])

    def hide_pov(self):
        for f in self.info["pov_files"]:
            (self.path / f).unlink(missing_ok=True)

    @property
    def fix_commit(self) -> str:
        return "human_patch"

    def apply_reference_fix(self) -> list[str]:
        taken = []
        for name, rel in self.info["patch_paths"].items():
            shutil.copy(self.hidden / "human_patch" / name, self.path / rel)
            taken.append(rel)
        bench = self.hidden / "human_patch.patch"
        if bench.exists():
            git(self.path, "apply", "--whitespace=nowarn", str(bench), check=False)
        return taken


class Vul4JBuilder:
    """The dataset's own compile and test commands, run through the `vul4j` command."""
    docker = "vul4j-image"

    def __init__(self, ws: Vul4JWorkspace, build_timeout: int = 1800, test_timeout: int = 2400, tests: str = "all"):
        self.ws = ws
        self.repo = ws.path
        self.target_files = ws.cve.target_files
        self.build_timeout = build_timeout
        self.test_timeout = test_timeout
        self.state_dir = self.repo / ".graphpatch"
        self.state_dir.mkdir(exist_ok=True)
        scope = self.state_dir / "test_scope"
        self.tests = scope.read_text(encoding="utf-8").strip() if scope.exists() else tests

    def compile(self) -> StepResult:
        argv = [*vul4j_cmd(), "compile", "-d", str(self.repo)]
        rc, log, secs = _run(argv, None, self.build_timeout)
        clog = self._read(VUL4J_DIR + "/compile.log")
        errors = [l.strip() for l in clog.splitlines() if ("[ERROR]" in l and ".java" in l) or ": error:" in l][:40]
        stage = "compile" if rc is not None else "compile_timeout"
        return StepResult(rc == 0, stage, " ".join(argv), rc, round(secs, 1), _tail(clog or log), errors)

    def _read(self, rel: str) -> str:
        p = self.repo / rel
        return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""

    def _test(self, batch: str) -> tuple[StepResult, dict]:
        res_file = self.repo / VUL4J_DIR / "testing_results.json"
        res_file.unlink(missing_ok=True)
        argv = [*vul4j_cmd(), "test", "-d", str(self.repo), "-b", batch]
        rc, log, secs = _run(argv, None, self.test_timeout)
        tlog = self._read(VUL4J_DIR + "/testing.log")
        if rc is None:
            return StepResult(False, "tests_timeout", " ".join(argv), None, round(secs, 1), _tail(tlog or log)), {}
        data = json.loads(res_file.read_text(encoding="utf-8")) if res_file.exists() else {}
        t = data.get("tests") or {}
        failed = sorted(f"{x['test_class']}#{x['test_method']}" for x in t.get("failures") or [])
        run = int((t.get("overall_metrics") or {}).get("number_running") or 0)
        return StepResult(rc == 0 and bool(data), "tests", " ".join(argv), rc, round(secs, 1), _tail(tlog or log),
                          failed_tests=failed, tests_run=run), data

    def test(self, baseline: bool = False) -> StepResult:
        if self.tests == "skip":
            return StepResult(False, "tests_skipped")
        res, _ = self._test("all")
        if res.stage == "tests_timeout":
            return res
        if baseline:
            (self.state_dir / "baseline_tests.json").write_text(
                json.dumps({"failed": res.failed_tests, "run": res.tests_run, "rc": res.returncode}), encoding="utf-8")
            return res
        res.new_failures = sorted(set(res.failed_tests) - set(self.baseline_failures()))
        res.ok = res.returncode == 0 and not res.new_failures and res.tests_run > 0
        if res.tests_run == 0:
            res.stage = "tests_none_ran"
        return res

    def run_pov(self) -> StepResult:
        """Put the hidden PoV tests back, run them, hide them again."""
        self.ws.restore_pov()
        try:
            res, _ = self._test("povs")
        finally:
            self.ws.hide_pov()
        if res.stage == "tests_timeout":
            return StepResult(False, "pov_timeout", res.command, None, res.seconds, res.log_tail)
        ran = res.tests_run > 0
        return StepResult(ran and not res.failed_tests, "pov" if ran else "pov_compile", res.command, res.returncode,
                          res.seconds, res.log_tail, failed_tests=res.failed_tests, tests_run=res.tests_run)

    def baseline_failures(self) -> list[str]:
        p = self.state_dir / "baseline_tests.json"
        return json.loads(p.read_text(encoding="utf-8"))["failed"] if p.exists() else []

    def has_baseline(self) -> bool:
        return (self.state_dir / "baseline_tests.json").exists()


class Vul4JValidator(Validator):
    def prepare_pov(self) -> dict:
        """Check once that the hidden PoV tests fail on the vulnerable code and pass on the human fix."""
        cache = self.builder.state_dir / "pov.json"
        if cache.exists():
            return json.loads(cache.read_text(encoding="utf-8"))
        ws = self.ws
        info = {"usable": False, "files": ws.info["pov_files"], "methods": ws.info["pov_tests"], "classes": [], "reason": ""}
        ws.reset()
        bug = self.builder.run_pov()
        ws.reset()
        ws.apply_reference_fix()
        fix = self.builder.run_pov() if self.builder.compile().ok else StepResult(False, "pov_compile")
        ws.reset()
        if bug.stage != "pov" or not bug.failed_tests:
            info["reason"] = f"PoV tests do not fail on the vulnerable code ({bug.stage}, {len(bug.failed_tests)} failing)"
        elif fix.stage != "pov" or fix.failed_tests:
            info["reason"] = f"PoV tests do not pass on the human fix ({fix.stage}, {len(fix.failed_tests)} failing)"
        else:
            info.update(usable=True, methods=sorted(bug.failed_tests))
        cache.write_text(json.dumps(info, indent=2), encoding="utf-8")
        return info

    def final(self, v: Verdict, pov: dict, graph_ref: dict | None = None, codeql=None) -> Verdict:
        compiled = bool(v.compile and v.compile.get("ok"))
        if v.status == "rejected":
            # Vul4J's own protocol only asks for compile + PoV: record the PoV result for compiled patches too,
            # the status stays rejected
            if compiled and pov.get("usable"):
                self._pov(v, pov)
            return v
        if pov.get("usable"):
            self._pov(v, pov)
        required = set((graph_ref or {}).get("removed_by_real_fix") or [])
        if required:
            v.graph_eval_ok = not (required & set(v.after_keys))
        run_codeql(v, codeql)
        oracles = [x for x in (v.graph_eval_ok, v.pov_ok, v.codeql_ok) if x is not None]
        v.status = "verified" if oracles and all(oracles) else "plausible"
        return v

    def _pov(self, v: Verdict, pov: dict):
        r = self.builder.run_pov()
        failed = set(r.failed_tests) & set(pov["methods"])
        v.pov_ok = r.stage == "pov" and not failed and r.tests_run > 0
        v.pov_failed = sorted(failed) if r.stage == "pov" else [f"({r.stage})"]
