import networkx as nx

from graphpatch_v2 import graph
from graphpatch_v2.taint import Finding


def _f(sink, steps, cwe="CWE-022", file="A.java"):
    return Finding(cwe, file, "A", "m", 9, sink, tuple(steps))


def test_paths_share_nodes_and_rank_choke_point():
    a = _f("mkdirs()", ["entry name (line 3)", "`name` = ... (line 3)", "new File(...) (line 4)", "SINK mkdirs() at line 5"])
    b = _f("FileOutputStream(...)", ["entry name (line 3)", "`name` = ... (line 3)", "new File(...) (line 4)", "SINK FileOutputStream(...) at line 6"])
    G = graph.build([a, b])
    assert isinstance(G, nx.DiGraph)
    assert G.number_of_nodes() == 5 and G.number_of_edges() == 4      # the shared prefix is one chain
    s = graph.summary(G)
    assert s["sources"] == 1 and s["sinks"] == 2 and s["reachable_sinks"] == 2 and s["is_dag"]
    top = graph.choke_points(G)[0]
    assert top["paths"] == 2 and "new File" in top["text"]
    assert graph.hot_files(G)[0] == {"file": "A.java", "nodes": 5, "edges": 4}


def test_export_formats(tmp_path):
    G = graph.build([_f("exec(...)", ["`cmd` parameter (line 2)", "SINK exec(...) at line 3"], cwe="CWE-078")])
    for ext in (".graphml", ".gexf", ".json"):
        graph.write(G, tmp_path / f"g{ext}")
        assert (tmp_path / f"g{ext}").stat().st_size > 0
    assert len(graph.to_json(G)["links"]) == 1


def test_empty_graph():
    s = graph.summary(graph.build([]))
    assert s["nodes"] == 0 and s["reachable_sinks"] == 0
