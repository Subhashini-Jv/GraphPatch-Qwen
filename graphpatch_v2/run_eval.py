"""GraphPatch v2 command line.

  python -m graphpatch_v2.run_eval calibrate [--limit N]
  python -m graphpatch_v2.run_eval run --mode oracle --cves CVE-2018-9159 CVE-2022-25842
  python -m graphpatch_v2.run_eval run --mode full --provider gemini --model <name> --limit 10
  python -m graphpatch_v2.run_eval summarize
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from .calibrate import calibrate
from .dataset import ensure_dataset
from .llm import LLM, LLMError, StopRun
from .pipeline import LLM_MODES, MODES, Config, run_cve

FIELDS = ["slug", "cve", "cwe", "mode", "model", "status", "stage", "iterations", "paths_before", "paths_after",
          "graph_ok", "graph_eval_ok", "paths_removed_by_real_fix", "pov_ok", "pov_usable", "pov_reason", "no_tests", "compile_ok", "tests_run", "new_test_failures", "baseline_failures", "deleted_targets", "llm_calls",
          "prompt_tokens", "completion_tokens", "context_chars", "file_context_chars", "graph_context_chars",
          "docker", "seconds", "error"]


def _suspect(r: dict) -> bool:
    """A build failure recorded before line endings were fixed (no "lf" flag) that shows the CRLF symptom
    ("sh\\r: No such file", a broken ./gradlew) is not a real exclusion: run it again. Maven builds use the
    system mvn, so their failures (missing artifacts etc.) are real and stay excluded."""
    if r.get("status") != "excluded" or r.get("stage") != "baseline_build_failed" or r.get("lf"):
        return False
    err = str(r.get("error") or "")
    return "\r" in err or "\\r" in err or "gradlew" in err


def _online() -> bool:
    import socket
    for host in ("generativelanguage.googleapis.com", "github.com"):
        try:
            socket.getaddrinfo(host, 443)
            return True
        except OSError:
            continue
    return False


def main(argv=None):
    ap = argparse.ArgumentParser(prog="graphpatch_v2")
    ap.add_argument("--root", default="gp_runs", help="where repos, caches and results go")
    ap.add_argument("--dataset", default=None, help="path to a CWE-Bench-Java clone (cloned into <root> if missing)")
    ap.add_argument("--benchmark", choices=["cwe-bench-java", "vul4j"], default="cwe-bench-java",
                    help="vul4j: run inside the Vul4J Docker image (see vul4j_run.ps1); results go to <root>/results_vul4j")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("calibrate", help="measure the taint checker on vulnerable vs. fixed code")
    c.add_argument("--cves", nargs="*")
    c.add_argument("--cwe")
    c.add_argument("--limit", type=int)

    r = sub.add_parser("run", help="repair CVEs")
    r.add_argument("--mode", choices=MODES, required=True)
    r.add_argument("--cves", nargs="*", help="CVE ids or project slugs")
    r.add_argument("--cwe")
    r.add_argument("--limit", type=int)
    r.add_argument("--provider", help="gemini | groq | openrouter | deepseek | openai | ollama")
    r.add_argument("--model")
    r.add_argument("--base-url")
    r.add_argument("--max-iters", type=int, default=3)
    r.add_argument("--tests", choices=["module", "related", "skip"], default="module")
    r.add_argument("--docker", choices=["auto", "always", "never"], default="auto")
    r.add_argument("--build-timeout", type=int, default=1800)
    r.add_argument("--test-timeout", type=int, default=2400)
    r.add_argument("--no-pov", action="store_true", help="skip held-out proof-of-vulnerability tests")
    r.add_argument("--codeql-oracle", nargs="?", const="auto", default=None, metavar="PATH",
                   help="add CodeQL as an independent held-out oracle (CodeQL bundle found as for codeql.py, or give its path)")
    r.add_argument("--codeql-timeout", type=int, default=3600, help="seconds per CodeQL analysis")
    r.add_argument("--paper-mode", "--core-only", action="store_true",
                   help="reproduce the original v2 runs: free-text Critic, exact/whitespace SEARCH matching only, the v2 guard rules "
                        "(the current paper describes the JSON Critic; do not use this for the paper's GraphPatch numbers)")
    r.add_argument("--free-critic", action="store_true",
                   help="free-text Critic as in the original paper runs (default: Critic answers in checked JSON)")
    r.add_argument("--tfidf-log", action="store_true",
                   help="kept for older commands; TF-IDF log terms are already on by default in full/seeded")
    r.add_argument("--no-tfidf-log", action="store_true",
                   help="do not give the Critic the TF-IDF key terms and lines of compile/test logs (on by default in full/seeded)")
    r.add_argument("--memory", metavar="PATH", default=None,
                   help="fix memory (JSON lines, default <root>/results/fix_memory.jsonl): up to 10 verified fixes from the "
                        "training split; the Planner gets the k most similar ones from OTHER repositories "
                        "(embeddings + KNN, cosine similarity; ml.py)")
    r.add_argument("--no-memory", action="store_true", help="run GraphPatch without the fix memory")
    r.add_argument("--memory-build", action="store_true",
                   help="fill the fix memory: store verified fixes of training-split CVEs (never the CVEs in "
                        "paper_cves.txt) and retrieve nothing; run this before the evaluation runs")
    r.add_argument("--memory-k", type=int, default=3, help="past fixes shown to the Planner (default 3)")
    r.add_argument("--cves-file", help="text file with one CVE id per line (e.g. graphpatch_v2/paper_cves.txt)")
    r.add_argument("--rpm", type=float, help="max model requests per minute (free Gemini tier: 5)")
    r.add_argument("--skip-done", action="store_true",
                   help="skip CVEs that already have a finished result for this mode and model (to continue a run another day)")
    r.add_argument("--redo-old-parser", action="store_true",
                   help="with --skip-done: also rerun results recorded before the v2.16 edit parser (see redo_runs.ps1)")

    s = sub.add_parser("summarize", help="print result tables")

    a = ap.parse_args(argv)
    root = Path(a.root).resolve()
    if a.benchmark == "vul4j":
        from .vul4j_bench import Vul4JDataset
        ds = Vul4JDataset(Path(a.dataset) if a.dataset else None)
        res = root / "results_vul4j"
        if a.cmd == "calibrate":
            sys.exit("error: calibrate is for CWE-Bench-Java; Vul4J is judged by its PoV tests")
    else:
        ds = ensure_dataset(Path(a.dataset) if a.dataset else root / "cwe-bench-java")
        res = root / "results"

    if a.cmd == "calibrate":
        cves = ds.select(a.cves, a.cwe, a.limit)
        out = res / "calibration.csv"
        out.with_suffix(".jsonl").unlink(missing_ok=True)
        rows = calibrate(ds, cves, root, out)
        print_calibration(rows)
        return

    if a.cmd == "run":
        from . import __version__
        print(f"GraphPatch {__version__} (code in {Path(__file__).parent})", flush=True)
        llm = None
        if a.mode in LLM_MODES:
            try:
                llm = LLM(a.provider, a.model, a.base_url, rpm=a.rpm)
                llm.retry_empty = True  # an empty API answer is a transport hiccup: ask again instead of losing the whole CVE run
            except LLMError as e:
                sys.exit(f"error: {e}")
        codeql_path = None
        if a.codeql_oracle:
            from .codeql import find_codeql
            try:
                codeql_path = find_codeql(None if a.codeql_oracle == "auto" else a.codeql_oracle)
            except FileNotFoundError as e:
                sys.exit(f"error: {e}")
        cfg = Config(root=root, out=res / "artifacts", max_iters=a.max_iters, tests=a.tests,
                     use_docker=a.docker, build_timeout=a.build_timeout, test_timeout=a.test_timeout,
                     pov=not a.no_pov, llm=llm, structured_critic=not (a.free_critic or a.paper_mode),
                     fuzzy_edits=not a.paper_mode, strict_guards=not a.paper_mode,
                     codeql=codeql_path, codeql_timeout=a.codeql_timeout,
                     tfidf_log=not a.no_tfidf_log, memory_k=a.memory_k, memory_build=a.memory_build,
                     memory=None if a.no_memory else (Path(a.memory) if a.memory else res / "fix_memory.jsonl"))
        ids = list(a.cves or [])
        if a.cves_file:
            ids += [l.split("#")[0].strip() for l in Path(a.cves_file).read_text(encoding="utf-8", errors="replace").splitlines() if l.split("#")[0].strip()]
        cves = ds.select(ids or None, a.cwe, None)
        jl = res / "runs.jsonl"
        jl.parent.mkdir(parents=True, exist_ok=True)
        model = getattr(llm, "model", "") if llm else ""
        if a.skip_done and jl.exists():
            old_rows = load(jl)
            done = {r["slug"] for r in old_rows if r.get("mode") == a.mode and (r.get("model") or "") == model
                    and r.get("status") in ("verified", "plausible", "rejected", "excluded") and not _suspect(r)
                    and (not a.redo_old_parser or r.get("parser") == 2 or r.get("status") == "excluded")
                    # results from before v3 (fuzzy edits, JSON Critic, stricter guards) are run again
                    and (r.get("gp") or 0) >= 3 and bool(r.get("paper_mode")) == a.paper_mode}
            # a CVE whose vulnerable version does not build or test is excluded before any model call, so the same
            # result holds for every mode: reuse it instead of spending hours on the same failing baseline again
            baseline = {}
            for r in old_rows:
                if r.get("status") == "excluded" and str(r.get("stage") or "").startswith("baseline_") and not _suspect(r):
                    baseline.setdefault(r["slug"], r)
            for c in cves:
                if c.slug in done or c.slug not in baseline:
                    continue
                b = baseline[c.slug]
                row = {**b, "mode": a.mode, "model": model, "iterations": 0, "seconds": 0, "prompt_tokens": 0,
                       "completion_tokens": 0, "llm_calls": 0, "error": f"baseline result reused from the {b.get('mode')} run"}
                print(f"[-] {c.cve_id} {c.cwe} mode={a.mode} -> excluded ({b.get('stage')}), same as the {b.get('mode')} run", flush=True)
                append_row(jl, row)
                done.add(c.slug)
            cves = [c for c in cves if c.slug not in done]
        if a.limit is not None:
            cves = cves[:a.limit]
        stopped = False
        for i, cve in enumerate(cves, 1):
            if not _online():
                print("    -> stopped: no internet connection. Nothing was recorded; run daily_run.ps1 again when you are back online.")
                stopped = True
                break
            print(f"[{i}/{len(cves)}] {cve.cve_id} {cve.cwe} mode={a.mode}", flush=True)
            try:
                row = run_cve(cve, ds, a.mode, cfg)
            except StopRun as e:
                print(f"    -> stopped: {e}. Nothing was recorded for this CVE; fix the problem or wait, then rerun with --skip-done.")
                stopped = True
                break
            if row.get("status") == "error" and not _online():
                # a lost connection is not a result: don't record it, so --skip-done runs this CVE again
                print(f"    -> stopped: the internet connection dropped during this CVE ({str(row.get('error'))[:120]}). "
                      "Nothing was recorded; run daily_run.ps1 again when you are back online.")
                stopped = True
                break
            print(f"    -> {row['status']} ({row.get('stage')}) paths {row.get('paths_before')}->{row.get('paths_after')} "
                  f"iters={row.get('iterations')} {row.get('seconds')}s {row.get('error', '') or ''}", flush=True)
            row["lf"] = True
            row["gp"] = 3      # v3: fuzzy SEARCH placement, JSON Critic, stricter guards, seeded mode, CodeQL oracle
            row["parser"] = 2  # v2.16 edit parser: blocks that share one FILE: line are kept
            append_row(jl, row)
        write_csv(jl, res / "runs.csv")
        print_summary(load(jl))
        if stopped:
            sys.exit(2)
        return

    if a.cmd == "summarize":
        jl = res / "runs.jsonl"
        if jl.exists():
            write_csv(jl, res / "runs.csv")
            print_summary(load(jl))
        cal = res / "calibration.jsonl"
        if cal.exists():
            print_calibration(load(cal))


def append_row(jl: Path, row: dict):
    # if the PC lost power while writing, the file can end in half a line: start the new row on a fresh line
    broken_end = jl.exists() and jl.stat().st_size > 0 and not jl.read_bytes().endswith(b"\n")
    with open(jl, "a", encoding="utf-8") as f:
        f.write(("\n" if broken_end else "") + json.dumps(row, default=str) + "\n")


def load(jl: Path) -> list[dict]:
    rows = []
    for n, l in enumerate(open(jl, encoding="utf-8", errors="replace"), 1):
        l = l.strip().strip("\x00")
        if not l:
            continue
        try:
            rows.append(json.loads(l))
        except json.JSONDecodeError:   # half-written line from a power cut: that CVE has no result and runs again
            print(f"note: skipping a damaged line {n} in {jl.name}", file=sys.stderr)
    latest = {}
    for r in rows:  # keep the most recent run per (mode, model, slug)
        latest[(r.get("mode"), r.get("model"), r.get("slug"))] = r
    return list(latest.values())


def write_csv(jl: Path, out: Path):
    with open(out, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        w.writeheader()
        w.writerows(load(jl))


def print_summary(rows: list[dict]):
    groups = defaultdict(list)
    for r in rows:
        groups[(r["mode"], r.get("model") or "-")].append(r)
    # Vul4J: also the dataset's own protocol (compiles + PoV tests pass, other tests not checked), for comparison
    # with published Vul4J results
    vul4j = any(r.get("docker") == "vul4j-image" for r in rows)
    extra = " PoV pass (Vul4J protocol) |" if vul4j else ""
    print("\n| mode | model | CVEs | excluded | errors | verified | plausible only | rejected | tests pass but still vulnerable | median tokens |" + extra)
    print("|---|---|---|---|---|---|---|---|---|---|" + ("---|" if vul4j else ""))
    for (mode, model), rs in sorted(groups.items()):
        st = Counter(r["status"] for r in rs)
        valid = [r for r in rs if r["status"] not in ("excluded", "error")]
        toks = sorted((r.get("prompt_tokens") or 0) + (r.get("completion_tokens") or 0) for r in valid)
        med = toks[len(toks) // 2] if toks else 0
        n = len(valid) or 1
        still_vuln = sum(1 for r in valid if r["status"] == "plausible" and (r.get("graph_eval_ok") is False or r.get("pov_ok") is False))
        print(f"| {mode} | {model} | {len(rs)} | {st['excluded']} | {st['error']} | {st['verified']} ({100*st['verified']/n:.0f}%) "
              f"| {st['plausible']} ({100*st['plausible']/n:.0f}%) | {st['rejected']} | {still_vuln} | {med} |"
              + (f" {sum(1 for r in valid if r.get('compile_ok') and r.get('pov_ok') is True)} |" if vul4j else ""))


def print_calibration(rows: list[dict]):
    ok = [r for r in rows if r.get("status") == "ok"]
    by = defaultdict(list)
    for r in ok:
        by[r["cwe"]].append(r)
    print("\n| CWE | CVEs | path found on vulnerable code | path removed by real fix | reduced by real fix |")
    print("|---|---|---|---|---|")
    for cwe, rs in sorted(by.items()) + [("all", ok)]:
        d = sum(1 for r in rs if r["detected"])
        cl = sum(1 for r in rs if r["cleared_by_fix"])
        rd = sum(1 for r in rs if r["reduced_by_fix"])
        print(f"| {cwe} | {len(rs)} | {d} | {cl} | {rd} |")
    print(f"\nskipped/errors: {len(rows) - len(ok)}")


if __name__ == "__main__":
    main()
