"""Turn GraphPatch v2 benchmark results into LaTeX macros for the paper.

Usage (from the folder that contains gp_runs/):
    python fill_results.py gp_runs/results/runs.jsonl --model qwen2.5-coder-24k > results.tex

Then put results.tex next to graphpatch.tex and rebuild the PDF. Every number in the
paper that comes from a model run is read from this file; a value that is missing
prints as a bold "?" so nothing unmeasured can slip into the paper unnoticed.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from pathlib import Path

# The 9 CWE-Bench-Java CVEs of Table III (the paper set minus the ones that do not build or test).
PAPER_CVES = [
    "CVE-2022-25842", "CVE-2018-1002201", "CVE-2018-1002200", "CVE-2018-1002202", "CVE-2018-17297",
    "CVE-2020-35460", "CVE-2018-12036", "CVE-2022-31194", "CVE-2022-26049",
]
LLM_MODES = ["single", "nograph", "full", "filectx", "nogate", "seeded"]
LETTER = {"verified": "V", "plausible": "P", "rejected": "R", "error": "E", "excluded": "X"}
LOOP_MODES = {"nograph", "full", "filectx", "nogate", "seeded"}


def load(path: Path, paper_mode: bool | None = None) -> list[dict]:
    """Latest row per (mode, model, slug), the same rule run_eval.summarize uses."""
    latest = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip().strip("\x00")
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if paper_mode is not None and bool(r.get("paper_mode")) != paper_mode:
            continue
        latest[(r.get("mode"), r.get("model"), r.get("slug"))] = r
    return list(latest.values())


def tex(key: str, value) -> str:
    return f"\\expandafter\\def\\csname gp@{key}\\endcsname{{{value}}}"


def fmt_int(x: float) -> str:
    return f"{round(x):,}"


def median(xs: list[float]) -> float | None:
    return statistics.median(xs) if xs else None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", type=Path, help="gp_runs/results/runs.jsonl")
    ap.add_argument("--model", required=True, help="model name used for the LLM modes, e.g. qwen2.5-coder-24k")
    ap.add_argument("--paper-mode", action="store_true", help="use the runs made with run_eval --paper-mode")
    a = ap.parse_args(argv)

    rows = load(a.runs, a.paper_mode)
    vals: dict[str, object] = {"model": a.model}
    missing = []

    for mode in LLM_MODES + ["rule"]:
        # the rule baseline uses no model, so its rows carry no model name
        by_cve = {r.get("cve"): r for r in rows if r.get("mode") == mode
                  and (mode == "rule" or (r.get("model") or "") == a.model)}
        got = [by_cve[c] for c in PAPER_CVES if c in by_cve]
        for c in PAPER_CVES:
            r = by_cve.get(c)
            if r is None:
                continue
            cell = LETTER.get(r.get("status"), "?")
            if mode in LOOP_MODES and cell in "VPR" and r.get("status") != "error":
                cell += f" ({r.get('iterations') or 1})"
            vals[f"{mode}@{c}"] = cell
        if len(got) < len(PAPER_CVES):
            missing.append(f"{mode}: {len(PAPER_CVES) - len(got)} of {len(PAPER_CVES)} CVEs missing")
            continue  # totals only from a complete set

        count = lambda s: sum(1 for r in got if r.get("status") == s)
        valid = [r for r in got if r.get("status") not in ("excluded", "error")]
        test_passing = [r for r in valid if r.get("status") in ("verified", "plausible")]
        still_vuln = [r for r in test_passing if r.get("status") == "plausible"
                      and (r.get("graph_eval_ok") is False or r.get("pov_ok") is False)]
        for key, val in [("V", count("verified")), ("P", count("plausible")), ("R", count("rejected")),
                         ("E", count("error")), ("X", count("excluded")),
                         ("passing", len(test_passing)), ("stillvuln", len(still_vuln))]:
            vals[f"{mode}@{key}"] = val
        for key, field in [("iters", "iterations"), ("intok", "prompt_tokens"),
                           ("outtok", "completion_tokens"), ("secs", "seconds")]:
            m = median([float(r.get(field) or 0) for r in valid])
            if m is not None:
                vals[f"{mode}@{key}"] = fmt_int(m)

        # enhancements (v3): fuzzy edit placement, checked JSON critiques, rule seeding
        vals[f"{mode}@fuzzy"] = sum(1 for r in valid if r.get("fuzzy_edits"))
        calls = sum(int(r.get("critic_calls") or 0) for r in valid)
        bad = sum(int(r.get("critic_invalid") or 0) for r in valid)
        vals[f"{mode}@critcalls"] = calls
        vals[f"{mode}@critvalid"] = f"{calls - bad}" if calls else "0"
        cov = [c for r in valid for c in (r.get("critic_path_coverage") or [])]
        if cov:
            vals[f"{mode}@critcov"] = f"{round(100 * statistics.median(cov))}\\%"
        judged = [r for r in valid if r.get("codeql_ok") is not None]
        if judged:   # only when the runs used --codeql-oracle
            vals[f"{mode}@cqjudged"] = len(judged)
            vals[f"{mode}@cqok"] = sum(1 for r in judged if r.get("codeql_ok"))
        if mode == "seeded":
            vals["seeded@rulealone"] = sum(1 for r in valid if r.get("seeded") and r.get("iterations") == 1
                                           and not r.get("llm_calls"))
            vals["seeded@rulealoneV"] = sum(1 for r in valid if r.get("seeded") and r.get("iterations") == 1
                                            and not r.get("llm_calls") and r.get("status") == "verified")

    # totals over the three LLM systems compared in RQ1 (B1, B3, GraphPatch)
    rq1 = ("single", "nograph", "full")
    for key in ("passing", "stillvuln"):
        if all(f"{m}@{key}" in vals for m in rq1):
            vals[f"all@{key}"] = sum(vals[f"{m}@{key}"] for m in rq1)

    print(f"% generated by fill_results.py from {a.runs.name}, model {a.model}")
    print("\n".join(tex(k, v) for k, v in vals.items()))
    for m in missing:
        print(f"warning: {m}", file=sys.stderr)


if __name__ == "__main__":
    main()
