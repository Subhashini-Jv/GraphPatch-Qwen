"""Patch acceptance: build, tests, the taint-path check, and held-out PoV tests.

Two oracles check security, and they play different roles:

* The taint-path check needs nothing but the code, so the repair loop uses it
  as feedback ("untrusted data still reaches X at line N").
* Proof-of-vulnerability (PoV) tests come from the human fix commit. They are
  held out: never shown to the agents, only run once on the final patch.

For the final verdict the graph check is scored against the real fix: the
patch must remove every taint path that the developers' fix removed (paths
the real fix leaves in place are not held against the patch).

Final status of a patch:
  verified   compiles, no new test failures, and every security oracle that
             applies to this CVE passes (at least one must apply). The oracles are
             the graph-versus-fix check, the PoV tests and, when enabled, CodeQL
             (codeql_oracle.py), an independent taint engine.
  plausible  compiles and tests pass, but a security oracle fails or none applies
  rejected   does not compile, breaks tests, or could not be applied
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .build import Builder
from .dataset import CVE
from .javasrc import methods_in, read
from .taint import SINKS, Finding, TargetSpec, find_paths, same_package_files
from .workspace import Workspace, overlay, pov_files, remove_overlay


# A failed build or test run with one of these in its log failed because of the network, not the patch
# (e.g. CVE-2022-26049: the Gradle wrapper download timed out). Such a run is recorded as an error and retried.
NETWORK_RE = re.compile(r"org\.gradle\.wrapper\.Download|Could not transfer artifact|UnknownHostException|"
                        r"SocketTimeoutException|java\.net\.ConnectException|Temporary failure in name resolution")


class NetworkFailure(Exception):
    pass


@dataclass
class Verdict:
    status: str                         # verified | plausible | rejected
    stage: str                          # where it stopped
    compile: dict | None = None
    tests: dict | None = None
    paths_before: int = 0
    paths_after: int | None = None
    remaining: list[str] = field(default_factory=list)
    graph_ok: bool | None = None        # all paths gone (what the loop sees); None = no path found on the vulnerable code
    graph_eval_ok: bool | None = None   # every path the real fix removed is also removed; None = the real fix removed none
    after_keys: list[str] = field(default_factory=list)
    pov_ok: bool | None = None          # None = no usable PoV tests for this CVE
    pov_failed: list[str] = field(default_factory=list)
    codeql_ok: bool | None = None       # None = CodeQL oracle not enabled, not applicable, or failed
    codeql: dict | None = None          # remaining / new alerts, or the error
    deleted_targets: list[str] = field(default_factory=list)
    feedback: str = ""

    def to_dict(self):
        return asdict(self)


def scan(repo: Path, spec: TargetSpec) -> list[Finding]:
    if spec.cwe not in SINKS:   # e.g. Vul4J's CWE-20 or XXE: the checker has no rules, so it reports nothing
        return []
    present = [f for f in spec.files if (Path(repo) / f).exists()]
    return find_paths(repo, TargetSpec(spec.cwe, present, spec.methods), same_package_files(repo, present))


def deleted_targets(repo: Path, cve: CVE) -> list[str]:
    """Vulnerable methods that no longer exist after the patch. A fix may legitimately delete
    code, but it is reported so a reviewer can judge."""
    gone = []
    for r in cve.main_fix_rows:
        name = r.get("method") or ""
        if not name:
            continue
        p = Path(repo) / r["file"]
        if not p.exists():
            gone.append(f"{r['file']} (file)")
        elif name not in {m.name for m in methods_in(read(p), r["file"])}:
            gone.append(f"{r['class']}.{name}")
    return sorted(set(gone))


def run_codeql(v: Verdict, codeql) -> None:
    """The optional CodeQL oracle (codeql_oracle.py) on the patch in the tree, when it applies to this CVE."""
    if codeql is not None and codeql.applies:
        v.codeql = codeql.check()
        v.codeql_ok = v.codeql["ok"]


class Validator:
    def __init__(self, ws: Workspace, spec: TargetSpec, builder: Builder, paths_before: list[Finding],
                 require_tests: bool = True):
        self.ws = ws
        self.repo = ws.path
        self.cve = ws.cve
        self.spec = spec
        self.builder = builder
        self.paths_before = paths_before
        self.require_tests = require_tests

    # ------------------------------------------------------------ in-loop check (no held-out data)

    @staticmethod
    def _network_problem(text: str) -> str | None:
        m = NETWORK_RE.search(text or "")
        return m.group(0) if m else None

    def check(self) -> Verdict:
        v = Verdict("rejected", "compile", paths_before=len(self.paths_before))
        c = self.builder.compile()
        v.compile = c.to_dict()
        if not c.ok:
            net = self._network_problem("\n".join(c.errors) + "\n" + (c.log_tail or ""))
            if net:
                raise NetworkFailure(f"the build could not download what it needs ({net}); this says nothing about the patch")
            v.feedback = "The patched project does not compile.\n" + "\n".join(c.errors[:25] or [c.log_tail[-2500:]])
            return v
        t = self.builder.test()
        v.tests = t.to_dict()
        if not (t.ok or (not self.require_tests and t.stage == "tests_skipped")):
            v.stage = t.stage
            if t.new_failures:
                v.feedback = "Tests that passed before the patch now fail:\n" + "\n".join(t.new_failures[:20]) + "\n" + t.log_tail[-2000:]
            elif t.stage == "tests_timeout":
                v.feedback = "The test run timed out."
            elif t.stage == "tests_none_ran":
                v.feedback = "No tests ran after the patch (test compilation may have broken).\n" + t.log_tail[-2000:]
            else:
                net = self._network_problem("\n".join(t.errors) + "\n" + (t.log_tail or ""))
                if net:
                    raise NetworkFailure(f"the tests could not reach the network ({net}); this says nothing about the patch")
                v.feedback = "The test run failed.\n" + "\n".join(t.errors[:20]) + "\n" + t.log_tail[-1500:]
            return v
        after = scan(self.repo, self.spec)
        v.paths_after = len(after)
        v.after_keys = sorted({f.key for f in after})
        v.remaining = [f.render() for f in after]
        v.deleted_targets = deleted_targets(self.repo, self.cve)
        v.stage = "graph"
        v.graph_ok = None if not self.paths_before else not after
        v.status = "plausible"
        if v.graph_ok is False:
            v.feedback = ("The project builds and tests pass, but untrusted data still reaches a dangerous call:\n\n"
                          + "\n\n".join(v.remaining[:5]))
        return v

    @staticmethod
    def loop_accepts(v: Verdict, use_graph: bool) -> bool:
        if v.status == "rejected":
            return False
        return v.graph_ok is not False if use_graph else True

    # ------------------------------------------------------------ held-out evaluation

    def prepare_pov(self) -> dict:
        """Find PoV tests: fix-commit tests that fail on the vulnerable code and pass on the real fix.
        Cached per workspace; leaves the workspace at the baseline."""
        cache = self.builder.state_dir / "pov.json"
        if cache.exists():
            return json.loads(cache.read_text(encoding="utf-8", errors="replace"))
        info = {"usable": False, "classes": [], "methods": [], "reason": ""}
        files = pov_files(self.ws)
        classes = sorted({Path(f).stem for f in files if f.endswith(".java")})
        info["files"] = files
        if not classes:
            info["reason"] = "the fix commit adds or changes no test classes"
        else:
            self.ws.reset()
            ov = overlay(self.ws, files)
            bug = self.builder.run_named_tests(classes)
            remove_overlay(self.ws, ov)
            if bug.stage != "pov":
                info["reason"] = f"fix tests do not run against the vulnerable code ({bug.stage})"
            else:
                self.ws.apply_reference_fix()
                ov = overlay(self.ws, files)
                fix = self.builder.run_named_tests(classes)
                remove_overlay(self.ws, ov)
                self.ws.reset()
                if fix.stage != "pov":
                    info["reason"] = f"fix tests do not run against the real fix ({fix.stage})"
                else:
                    methods = sorted(set(bug.failed_tests) - set(fix.failed_tests))
                    info.update(usable=bool(methods), classes=classes, methods=methods,
                                reason="" if methods else "no fix test fails on the vulnerable code")
        self.ws.reset()
        cache.write_text(json.dumps(info, indent=2), encoding="utf-8")
        return info

    def prepare_graph_reference(self) -> dict:
        """Paths the real fix removes. Held out like PoV tests: used only for the final verdict."""
        cache = self.builder.state_dir / "graph_ref.json"
        if cache.exists():
            return json.loads(cache.read_text(encoding="utf-8", errors="replace"))
        before = sorted({f.key for f in self.paths_before})
        self.ws.reset()
        self.ws.apply_reference_fix()
        after_fix = sorted({f.key for f in scan(self.repo, self.spec)})
        self.ws.reset()
        info = {"before": before, "after_real_fix": after_fix,
                "removed_by_real_fix": sorted(set(before) - set(after_fix))}
        cache.write_text(json.dumps(info, indent=2), encoding="utf-8")
        return info

    def final(self, v: Verdict, pov: dict, graph_ref: dict | None = None, codeql=None) -> Verdict:
        """Run the held-out checks on the patch in the tree and settle the final status.
        `codeql` is an optional CodeQLOracle (codeql_oracle.py) whose reference is already prepared."""
        if v.status == "rejected":
            return v
        required = set((graph_ref or {}).get("removed_by_real_fix") or [])
        if required:
            v.graph_eval_ok = not (required & set(v.after_keys))
        if pov.get("usable"):
            ov = overlay(self.ws, pov["files"])
            r = self.builder.run_named_tests(pov["classes"])
            remove_overlay(self.ws, ov)
            failed = set(r.failed_tests) & set(pov["methods"])
            v.pov_ok = r.stage == "pov" and not failed
            v.pov_failed = sorted(failed) if r.stage == "pov" else [f"({r.stage})"]
        run_codeql(v, codeql)
        oracles = [x for x in (v.graph_eval_ok, v.pov_ok, v.codeql_ok) if x is not None]
        v.status = "verified" if oracles and all(oracles) else "plausible"
        return v
