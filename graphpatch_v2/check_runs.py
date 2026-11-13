"""Show which model and ML options produced each result row (read only).

    python -m graphpatch_v2.check_runs gp_runs/results/runs.jsonl [--mode full]

Rows written before v3.4 have no tfidf_log/memory fields. For those, a row counts as "TF-IDF on" when it has
tfidf_keywords, and as "memory on" when it has memory_hits or memory_embedder. A row with neither is reported as
"off / not recorded": nothing in it shows the option was used. TF-IDF runs only after a failed gate, so an old row
verified on the first iteration shows no keywords even if --tfidf-log was given; check the command you ran too.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def flags(r: dict) -> tuple[str, str, str]:
    tf = r.get("tfidf_log")
    if tf is None:
        tf = bool(r.get("tfidf_keywords"))
    mem = r.get("memory")
    mem_on = bool(mem) if "memory" in r else ("memory_hits" in r or bool(r.get("memory_embedder")))
    return ("on" if tf else "off / not recorded", "on" if mem_on else "off / not recorded", r.get("critic") or "not recorded")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("runs")
    ap.add_argument("--mode", default="full")
    a = ap.parse_args(argv)
    latest = {}
    for line in Path(a.runs).read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        if r.get("mode") == a.mode:
            latest[(r.get("model"), r.get("slug"))] = r
    if not latest:
        print(f"no rows for mode {a.mode!r}")
        return
    print(f"{'model':28} {'cve':18} {'status':10} {'tfidf':20} {'memory':20} critic")
    summary = Counter()
    for (model, _), r in sorted(latest.items(), key=lambda kv: (str(kv[0][0]), str(kv[0][1]))):
        tf, mem, critic = flags(r)
        summary[(model, tf, mem, critic)] += 1
        print(f"{str(model):28} {str(r.get('cve')):18} {str(r.get('status')):10} {tf:20} {mem:20} {critic}")
    print("\nsummary (model, tfidf, memory, critic): rows")
    for k, n in summary.items():
        print(f"  {k}: {n}")


if __name__ == "__main__":
    main()
