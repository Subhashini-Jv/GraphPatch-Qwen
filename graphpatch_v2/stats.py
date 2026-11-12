"""Statistics of the paper's Section V-B: Wilson 95% intervals for verified counts and exact McNemar tests
on the per-vulnerability outcomes (verified or not) of GraphPatch against each baseline.

  python -m graphpatch_v2.stats gp_runs/results/runs.jsonl --model <model> [--vs single nograph rule seeded]

Uses the latest row per (mode, model, CVE), like run_eval summarize. The rule baseline has no model name.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path


def wilson(k: int, n: int, z: float = 1.959964) -> tuple[float, float]:
    """Wilson score interval for k successes out of n."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - h), min(1.0, c + h))


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value from the discordant counts b and c (binomial test, p = 0.5)."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def compare(a: dict[str, bool], b: dict[str, bool]) -> dict:
    """Paired comparison over the CVEs both systems ran."""
    common = sorted(set(a) & set(b))
    only_a = sum(1 for c in common if a[c] and not b[c])
    only_b = sum(1 for c in common if b[c] and not a[c])
    return {"n": len(common), "only_first": only_a, "only_second": only_b, "p": mcnemar_exact(only_a, only_b)}


def load(path: Path, model: str) -> dict[str, dict[str, bool]]:
    latest = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        latest[(r.get("mode"), r.get("model"), r.get("cve"))] = r
    out: dict[str, dict[str, bool]] = {}
    for (mode, m, cve), r in latest.items():
        if mode == "rule" or (m or "") == model:
            if r.get("status") in ("excluded",):
                continue
            out.setdefault(mode, {})[cve] = r.get("status") == "verified"
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", type=Path)
    ap.add_argument("--model", required=True)
    ap.add_argument("--system", default="full", help="the system compared with the baselines (default: full)")
    ap.add_argument("--vs", nargs="*", default=["single", "nograph", "rule", "seeded"])
    a = ap.parse_args(argv)
    res = load(a.runs, a.model)
    for mode in [a.system] + a.vs:
        if mode in res:
            k, n = sum(res[mode].values()), len(res[mode])
            lo, hi = wilson(k, n)
            print(f"{mode:8} verified {k}/{n}  Wilson 95% {100 * lo:.0f}-{100 * hi:.0f}%")
    if a.system not in res:
        raise SystemExit(f"no rows for mode {a.system} and model {a.model}")
    for mode in a.vs:
        if mode in res:
            c = compare(res[a.system], res[mode])
            print(f"{a.system} vs {mode}: {c['only_first']} only {a.system}, {c['only_second']} only {mode}, "
                  f"exact McNemar p = {c['p']:.2f} (n = {c['n']})")


if __name__ == "__main__":
    main()
