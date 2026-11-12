"""Measure the taint checker against the benchmark's real fixes.

For every CVE: run the checker on the vulnerable commit and on the last fix
commit. A good checker finds a path on the vulnerable code (detected) and the
real fix removes it (cleared). These numbers bound how much the graph check
can be trusted, and belong in the paper's threats-to-validity section.
"""

from __future__ import annotations

import csv
import json
import time
import traceback
from pathlib import Path

from .dataset import CVE, Dataset
from .taint import TargetSpec, find_paths, same_package_files
from .workspace import files_at_commit


def spec_for(cve: CVE) -> TargetSpec:
    return TargetSpec(cve.cwe, cve.target_files, target_method_keys(cve))


def target_method_keys(cve: CVE) -> set[tuple]:
    keys = set()
    for r in cve.main_fix_rows:
        sig = (r.get("signature") or "").strip()
        n = None
        if "(" in sig:
            inner = sig[sig.index("(") + 1: sig.rindex(")")].strip()
            n = 0 if not inner else inner.count(",") + 1 - _generic_commas(inner)
        keys.add((r["file"], r.get("method") or "", n))
    return keys


def _generic_commas(s: str) -> int:
    depth = extra = 0
    for ch in s:
        if ch == "<":
            depth += 1
        elif ch == ">":
            depth -= 1
        elif ch == "," and depth > 0:
            extra += 1
    return extra


def calibrate_one(cve: CVE, root: Path) -> dict:
    row = {"slug": cve.slug, "cve": cve.cve_id, "cwe": cve.cwe, "targets": len(cve.target_files)}
    if not cve.target_files:
        row["status"] = "no main-source target files in fix_info"
        return row
    spec = spec_for(cve)
    from .workspace import final_fix_commit
    cache = Path(root) / "cache" / cve.repo_url.rstrip("/").split("github.com/")[-1].replace("/", "__")
    files_at_commit(root, cve, cve.buggy_commit, cve.target_files, Path(root) / "calib" / f"{cve.slug}__buggy")
    fix = final_fix_commit(cache, cve)
    row["fix_commit"] = fix
    for label, commit in (("buggy", cve.buggy_commit), ("fixed", fix)):
        dest = Path(root) / "calib" / f"{cve.slug}__{label}"
        present = files_at_commit(root, cve, commit, cve.target_files, dest)
        fs = find_paths(dest, spec, same_package_files(dest, present))
        row[f"{label}_paths"] = len(fs)
        row[f"{label}_keys"] = sorted({f.key for f in fs})
    row["detected"] = row["buggy_paths"] > 0
    row["cleared_by_fix"] = row["detected"] and row["fixed_paths"] == 0
    row["reduced_by_fix"] = row["detected"] and len(set(row["fixed_keys"]) & set(row["buggy_keys"])) < len(set(row["buggy_keys"]))
    row["status"] = "ok"
    return row


def calibrate(ds: Dataset, cves: list[CVE], root: Path, out: Path) -> list[dict]:
    rows = []
    out.parent.mkdir(parents=True, exist_ok=True)
    for i, c in enumerate(cves, 1):
        t = time.time()
        try:
            r = calibrate_one(c, root)
        except Exception as e:
            r = {"slug": c.slug, "cve": c.cve_id, "cwe": c.cwe, "status": f"error: {e}"[:300]}
            traceback.print_exc()
        r["seconds"] = round(time.time() - t, 1)
        rows.append(r)
        print(f"[{i}/{len(cves)}] {c.cve_id} {c.cwe} buggy={r.get('buggy_paths')} fixed={r.get('fixed_paths')} {r['status'][:60]}", flush=True)
        with open(out.with_suffix(".jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(r) + "\n")
    fields = ["slug", "cve", "cwe", "targets", "buggy_paths", "fixed_paths", "detected", "cleared_by_fix", "reduced_by_fix", "status", "seconds"]
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    return rows
