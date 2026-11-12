"""CodeQL as an independent, held-out oracle for the final verdict.

The paper's graph-versus-fix oracle reuses the javalang query that also drives gate G3, which favours
GraphPatch (Threats to Validity). CodeQL is a separate, sound-er taint engine with its own sources, sinks
and sanitizers, so it can judge a patch without sharing the loop's blind spots. Building a CodeQL database
takes minutes, too slow to run after every candidate, so it is used like the PoV tests: never shown to an
agent, run once on the vulnerable code, once on the developers' fix and once on the final patch.

A CVE is judgeable by CodeQL when CodeQL reports a path on the vulnerable code (restricted to the files
the real fix changes) and the fix removes at least one. For such a CVE the patch passes when

  * every alert the real fix removes is gone, and
  * the patch adds no alert in those files that neither the vulnerable code nor the real fix has.

The second rule is deliberately strict: alerts are keyed by the code text at source and sink, so a patch
that only rewrites the sink line (`new File(dir, clean(name))` with a `clean` that does nothing) would
otherwise make the old alert disappear while the path stays open.

Enable with `run_eval run ... --codeql-oracle` (CodeQL bundle found as in codeql.py, or pass a path).
CVEs that CodeQL makes judgeable but javalang does not can then be evaluated too (their loop runs
without a path gate, since javalang reports nothing); `python -m graphpatch_v2.codeql judgeable`
lists them from the CodeQL calibration.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from . import codeql as cq


class CodeQLOracle:
    def __init__(self, codeql: str, ws, cve, state_dir: Path, timeout: int = 3600):
        self.codeql = codeql
        self.ws = ws
        self.cve = cve
        self.work = Path(state_dir) / "codeql"
        self.timeout = timeout
        self.ref: dict = {}

    # ---------------------------------------------------------------- analysis of the tree as it is now

    def alerts(self) -> set[str]:
        """Keys of the CodeQL taint alerts for this CVE's CWE that touch the files the real fix changes."""
        self.work.mkdir(parents=True, exist_ok=True)
        try:
            sarif = cq.analyze(self.codeql, self.ws.path, self.work, self.timeout)
        finally:
            shutil.rmtree(self.work / "db", ignore_errors=True)
        return {a.key for a in cq.parse_sarif(sarif, self.cve.cwe, self.ws.path, self.cve.target_files)}

    # ---------------------------------------------------------------- held-out reference (before the loop)

    def prepare_reference(self) -> dict:
        """Alerts on the vulnerable code and on the developers' fix. Cached; leaves the workspace at the baseline."""
        cache = self.work.parent / "codeql_ref.json"
        if cache.exists():
            self.ref = json.loads(cache.read_text(encoding="utf-8", errors="replace"))
            return self.ref
        info = {"before": [], "after_real_fix": [], "removed_by_real_fix": [], "error": ""}
        try:
            self.ws.reset()
            before = self.alerts()
            info["before"] = sorted(before)
            if before:
                self.ws.apply_reference_fix()
                after = self.alerts()
                info["after_real_fix"] = sorted(after)
                info["removed_by_real_fix"] = sorted(before - after)
        except Exception as e:      # a CodeQL failure must not cost the repair run: the oracle just does not apply
            info["error"] = f"{type(e).__name__}: {e}"[:500]
        finally:
            self.ws.reset()
        self.work.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(info, indent=2), encoding="utf-8")
        self.ref = info
        return info

    @property
    def applies(self) -> bool:
        return bool(self.ref.get("removed_by_real_fix"))

    # ---------------------------------------------------------------- final check (patch in the tree)

    def check(self) -> dict:
        """Judge the patch now in the workspace. ok is None when the oracle does not apply or CodeQL failed."""
        if not self.applies:
            return {"ok": None, "remaining": [], "new": [], "error": self.ref.get("error", "")}
        try:
            now = self.alerts()
        except Exception as e:
            return {"ok": None, "remaining": [], "new": [], "error": f"{type(e).__name__}: {e}"[:500]}
        return judge(self.ref, now)


def judge(ref: dict, now: set[str]) -> dict:
    required = set(ref.get("removed_by_real_fix") or [])
    remaining = sorted(required & now)
    # alerts the developers' own fix also has are not held against the patch
    new = sorted(now - set(ref.get("before") or []) - set(ref.get("after_real_fix") or []))
    return {"ok": not remaining and not new, "remaining": remaining, "new": new, "error": ""}
