"""The program-wide taint graph as a NetworkX graph.

taint.py finds each source-to-sink path with its fixed-point propagation (paper, Section III-B).
This module joins those paths into one directed graph of the program, so that graph algorithms can
be run on it: which files carry the most tainted flow, which statements most paths go through
(a guard there breaks many paths at once), and whether a sink is still reachable from a source.

Nodes are statements on a path (keyed by file, line and text, so the same statement shared by two
paths is one node); edges are the data-flow hops between them.

    python -m graphpatch_v2.graph <project> [--cwe all|CWE-022,...] [--out graph.graphml|graph.json|graph.gexf]
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from pathlib import Path

import networkx as nx

LINE = re.compile(r"line (\d+)")


def _node_id(f, i: int, step: str) -> str:
    if step == "...":                      # elided hops are never shared between paths
        return f"{f.key}#gap{i}"
    m = LINE.search(step)
    return f"{f.file}:{m.group(1) if m else '?'}:{step.replace('SINK ', '')}"


def build(findings) -> nx.DiGraph:
    """One directed graph holding every taint path (taint.Finding objects)."""
    G = nx.DiGraph()
    for f in findings:
        prev = None
        for i, step in enumerate(f.steps):
            kind = "source" if i == 0 else "sink" if i == len(f.steps) - 1 else "step"
            nid = _node_id(f, i, step)
            m = LINE.search(step)
            if nid not in G:
                G.add_node(nid, kind=kind, text=step.replace("SINK ", ""), file=f.file,
                           line=int(m.group(1)) if m else -1, cwes="", findings=0)
            n = G.nodes[nid]
            if kind != "step":             # a node that is a source or sink of any path keeps that role
                n["kind"] = kind if n["kind"] == "step" else n["kind"]
            n["findings"] += 1
            n["cwes"] = ",".join(sorted(set(filter(None, n["cwes"].split(","))) | {f.cwe}))
            if prev is not None and prev != nid:
                if G.has_edge(prev, nid):
                    G.edges[prev, nid]["paths"] += 1
                else:
                    G.add_edge(prev, nid, cwe=f.cwe, paths=1)
            prev = nid
    return G


def sources(G):
    return [n for n, d in G.nodes(data=True) if d["kind"] == "source"]


def sinks(G):
    return [n for n, d in G.nodes(data=True) if d["kind"] == "sink"]


def reachable_sinks(G) -> int:
    """How many sink nodes some source still reaches (0 once every path is broken)."""
    seen = set()
    for s in sources(G):
        seen |= nx.descendants(G, s)
    return sum(1 for t in sinks(G) if t in seen)


def hot_files(G, top: int = 10) -> list[dict]:
    """Files ranked by how many tainted statements (nodes) and hops (edges) they hold."""
    nodes = Counter(d["file"] for _, d in G.nodes(data=True))
    edges = Counter(G.nodes[u]["file"] for u, _ in G.edges())
    return [{"file": f, "nodes": n, "edges": edges.get(f, 0)} for f, n in nodes.most_common(top)]


def choke_points(G, top: int = 5) -> list[dict]:
    """Statements that lie on the most source-to-sink flow (betweenness centrality): where one guard helps most."""
    if G.number_of_nodes() < 3:
        return []
    bc = nx.betweenness_centrality(G)
    ranked = sorted((n for n in G if G.nodes[n]["kind"] == "step"), key=lambda n: (-bc[n], -G.nodes[n]["findings"]))
    return [{"node": n, "text": G.nodes[n]["text"], "file": G.nodes[n]["file"], "line": G.nodes[n]["line"],
             "paths": G.nodes[n]["findings"], "betweenness": round(bc[n], 4)} for n in ranked[:top] if bc[n] > 0]


def summary(G) -> dict:
    return {"nodes": G.number_of_nodes(), "edges": G.number_of_edges(), "sources": len(sources(G)), "sinks": len(sinks(G)),
            "reachable_sinks": reachable_sinks(G), "components": nx.number_weakly_connected_components(G) if len(G) else 0,
            "is_dag": nx.is_directed_acyclic_graph(G), "longest_path": nx.dag_longest_path_length(G) if len(G) and nx.is_directed_acyclic_graph(G) else None}


def to_json(G) -> dict:
    return nx.node_link_data(G, edges="links")


def write(G, out: Path):
    out = Path(out)
    if out.suffix == ".graphml":
        nx.write_graphml(G, out)
    elif out.suffix == ".gexf":
        nx.write_gexf(G, out)
    else:
        out.write_text(json.dumps(to_json(G), indent=1), encoding="utf-8")


def main(argv=None):
    from .scanner import scan_repo
    from .taint import SINKS
    ap = argparse.ArgumentParser(prog="python -m graphpatch_v2.graph", description=__doc__.split("\n\n")[0])
    ap.add_argument("project", type=Path)
    ap.add_argument("--cwe", default="all", help="all, or a comma list such as CWE-022,CWE-078")
    ap.add_argument("--out", type=Path, help="write the graph (.graphml, .gexf or .json)")
    a = ap.parse_args(argv)
    cwes = list(SINKS) if a.cwe == "all" else [c.strip() for c in a.cwe.split(",")]
    G = build(scan_repo(a.project, cwes))
    print(json.dumps({"summary": summary(G), "hot_files": hot_files(G), "choke_points": choke_points(G)}, indent=2))
    if a.out:
        write(G, a.out)
        print(f"graph written to {a.out}")


if __name__ == "__main__":
    main()
