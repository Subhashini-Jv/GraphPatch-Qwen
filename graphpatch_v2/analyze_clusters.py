"""K-Means clustering of the benchmark CVEs by difficulty, and how each system did per cluster.

  python -m graphpatch_v2.analyze_clusters gp_runs/results/runs.jsonl --model <model> [--k 3] [--out clusters.csv]

Features per CVE come from the run records and do not depend on the model or the mode:
  paths_before         taint paths on the vulnerable code (more paths = more places to break)
  file_context_chars   size of the vulnerable files (code size)
  graph_context_chars  size of the path-sliced context (how spread out the flow is)
They are log-scaled and standardized (z-scores), then clustered with K-Means (k-means++ init, 20 restarts,
fixed seed). Clusters are named Easy, Medium, Hard by the mean z-score of their centroid.

The silhouette score says how well separated the clusters are (1 = clean, about 0 = no structure). With few
CVEs (the paper has 9) the clustering is descriptive only: it is a way to group the cases, not a test, and the
script prints a warning below 15 CVEs.
"""

from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

FEATURES = ("paths_before", "file_context_chars", "graph_context_chars")
NAMES = {2: ["Easy", "Hard"], 3: ["Easy", "Medium", "Hard"]}


def load_rows(path: Path) -> list[dict]:
    rows = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def features(rows: list[dict]) -> dict[str, list[float]]:
    """One feature vector per CVE, from the latest row that has all features."""
    out = {}
    for r in rows:
        if all(isinstance(r.get(f), (int, float)) for f in FEATURES):
            out[r["cve"]] = [float(r[f]) for f in FEATURES]
    return out


def outcomes(rows: list[dict], model: str) -> dict[str, dict[str, bool]]:
    """mode -> CVE -> verified, latest row per (mode, model, CVE); the rule baseline has no model."""
    latest = {}
    for r in rows:
        latest[(r.get("mode"), r.get("model") or "", r.get("cve"))] = r
    res: dict[str, dict[str, bool]] = {}
    for (mode, m, cve), r in latest.items():
        if (mode == "rule" or m == model) and r.get("status") != "excluded":
            res.setdefault(mode, {})[cve] = r.get("status") == "verified"
    return res


def cluster(feats: dict[str, list[float]], k: int = 3, seed: int = 0) -> tuple[dict[str, str], float | None, list]:
    import numpy as np
    from sklearn.cluster import KMeans
    from sklearn.metrics import silhouette_score
    from sklearn.preprocessing import StandardScaler

    cves = sorted(feats)
    if len(cves) < k:
        raise ValueError(f"need at least k={k} CVEs with features, got {len(cves)}")
    X = StandardScaler().fit_transform(np.log1p(np.array([feats[c] for c in cves])))
    km = KMeans(n_clusters=k, n_init=20, random_state=seed).fit(X)
    order = np.argsort(km.cluster_centers_.mean(axis=1))          # lowest mean z-score = easiest
    names = NAMES.get(k) or [f"C{i + 1}" for i in range(k)]
    label_name = {int(c): names[rank] for rank, c in enumerate(order)}
    sil = float(silhouette_score(X, km.labels_)) if 1 < k < len(cves) and len(set(km.labels_)) > 1 else None
    return {c: label_name[int(l)] for c, l in zip(cves, km.labels_)}, sil, km.cluster_centers_.tolist()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("runs", type=Path)
    ap.add_argument("--model", required=True, help="model name of the LLM runs to compare")
    ap.add_argument("--k", type=int, default=3)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--modes", nargs="*", default=["rule", "single", "nograph", "full", "seeded"])
    ap.add_argument("--out", type=Path, help="write one row per CVE (features, cluster, outcome per mode) as CSV")
    a = ap.parse_args(argv)

    rows = load_rows(a.runs)
    feats = features(rows)
    res = outcomes(rows, a.model)
    labels, sil, _ = cluster(feats, a.k, a.seed)
    names = NAMES.get(a.k) or sorted(set(labels.values()))
    modes = [m for m in a.modes if m in res]

    if len(labels) < 15:
        print(f"note: only {len(labels)} CVEs; the clusters describe this set, they are not a statistical result.")
    print(f"K-Means, k={a.k}, features {', '.join(FEATURES)} (log, z-scored); "
          f"silhouette {'n/a' if sil is None else f'{sil:.2f}'}\n")
    print(f"{'cluster':8} {'CVEs':>4}  " + "  ".join(f"{m:>8}" for m in modes))
    for name in names:
        group = [c for c, l in labels.items() if l == name]
        if not group:
            continue
        cells = []
        for m in modes:
            ran = [c for c in group if c in res[m]]
            cells.append(f"{sum(res[m][c] for c in ran)}/{len(ran)}".rjust(8))
        print(f"{name:8} {len(group):>4}  " + "  ".join(cells))
    print()
    for name in names:
        for c in sorted(c for c, l in labels.items() if l == name):
            f = feats[c]
            print(f"  {name:6} {c:18} paths={f[0]:.0f} file_chars={f[1]:.0f} path_chars={f[2]:.0f}")
    if a.out:
        with a.out.open("w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["cve", "cluster", *FEATURES, *modes])
            for c in sorted(labels):
                w.writerow([c, labels[c], *[int(x) for x in feats[c]],
                            *[("V" if res[m][c] else "-") if c in res[m] else "" for m in modes]])
        print(f"\nwritten to {a.out}")


if __name__ == "__main__":
    main()
