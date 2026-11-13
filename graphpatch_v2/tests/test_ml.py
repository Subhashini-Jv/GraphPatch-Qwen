"""TF-IDF log terms, fix memory (embeddings + KNN cosine retrieval) and K-Means difficulty clusters."""

import json

import numpy as np
import pytest

pytest.importorskip("sklearn")

from graphpatch_v2 import analyze_clusters as ac
from graphpatch_v2 import ml

MAVEN_LOG = """[INFO] Scanning for projects...
[INFO] Building demo 1.0
[INFO] --- maven-compiler-plugin:3.8.1:compile (default-compile) @ demo ---
[INFO] Compiling 12 source files to target/classes
[ERROR] /src/main/java/demo/Unzip.java:[45,17] cannot find symbol
[ERROR]   symbol:   class FilenameUtils
[ERROR]   location: class demo.Unzip
[ERROR] /src/main/java/demo/Unzip.java:[52,9] cannot find symbol
[ERROR]   symbol:   variable FilenameUtils
[INFO] BUILD FAILURE
[INFO] Total time: 3.2 s
[ERROR] To see the full stack trace of the errors, re-run Maven with the -e switch."""


def test_tfidf_ranks_by_score_not_alphabet():
    s = ml.log_keywords(MAVEN_LOG, top=5)
    assert "filenameutils" in s.keywords
    assert "symbol" in s.keywords
    assert "info" not in s.keywords and "build" not in s.keywords
    assert any("cannot find symbol" in l for l in s.lines)


def test_augment_keeps_the_full_log_and_skips_graph_feedback():
    fb, kws = ml.augment_feedback(MAVEN_LOG, "compile")
    assert fb.startswith("KEY TERMS IN THE LOG") and MAVEN_LOG in fb and kws
    assert ml.augment_feedback("untrusted data still reaches", "graph") == ("untrusted data still reaches", [])
    assert ml.augment_feedback(MAVEN_LOG, "tests_failed")[1]


def _mem(tmp_path):
    m = ml.FixMemory(tmp_path / "mem.jsonl", embedder=ml.Embedder("tfidf"))
    m.add("CVE-1", "https://github.com/a/zip", "CWE-022", "ZipEntry getName new File destDir entryName extract",
          "", "+ if (!f.getCanonicalPath().startsWith(base)) throw")
    m.add("CVE-2", "https://github.com/b/http", "CWE-022", "HttpServletRequest getParameter response writer html",
          "", "+ escape(html)")
    m.add("CVE-3", "https://github.com/c/tar", "CWE-022", "TarEntry getName new File outputDir entryName extract",
          "", "+ normalize path")
    return m


def test_knn_returns_the_most_similar_fix_first(tmp_path):
    hits = _mem(tmp_path).query("ZipEntry entry getName File outDir entryName extract archive", "CVE-9",
                                "https://github.com/z/new", "CWE-022", k=2)
    assert [h.cve for h in hits][0] == "CVE-1"
    assert hits[0].similarity >= hits[-1].similarity > 0


def test_memory_never_returns_same_cve_or_repo(tmp_path):
    m = _mem(tmp_path)
    hits = m.query("ZipEntry getName new File destDir entryName extract", "CVE-1", "https://github.com/a/zip", k=3)
    assert "CVE-1" not in [h.cve for h in hits]
    hits = m.query("ZipEntry getName new File destDir entryName extract", "CVE-X", "https://github.com/c/tar", k=3)
    assert "CVE-3" not in [h.cve for h in hits]


def test_memory_filters_by_cwe_and_empty_store(tmp_path):
    assert ml.FixMemory(tmp_path / "none.jsonl", embedder=ml.Embedder("tfidf")).query("x y z", "C", "r") == []
    assert _mem(tmp_path).query("ZipEntry getName", "CVE-9", "r", cwe="CWE-078") == []


def test_dense_embedder_path(tmp_path):
    class Fake(ml.Embedder):
        def __init__(self):
            self.kind = "fake-384"

        def embed(self, texts):
            v = np.array([[t.count("Zip"), t.count("Http"), 1.0] for t in texts])
            return v / np.linalg.norm(v, axis=1, keepdims=True)
    m = ml.FixMemory(tmp_path / "mem.jsonl", embedder=Fake())
    m.add("CVE-1", "r1", "CWE-022", "Zip Zip", "", "d1")
    m.add("CVE-2", "r2", "CWE-022", "Http Http", "", "d2")
    assert m.query("Zip", "CVE-9", "r9", k=1)[0].cve == "CVE-1"
    assert "similarity" in ml.render_examples(m.query("Zip", "CVE-9", "r9", k=1))


def _rows():
    rows = []
    shapes = {"E1": (1, 3000, 1500), "E2": (1, 3500, 1600), "E3": (2, 4000, 1800),
              "M1": (4, 9000, 5000), "M2": (5, 10000, 5500), "M3": (4, 11000, 6000),
              "H1": (16, 30000, 15000), "H2": (14, 28000, 14000), "H3": (18, 35000, 16000)}
    for cve, (p, fc, gc) in shapes.items():
        for mode, ok in (("rule", cve.startswith("E")), ("full", not cve.startswith("H1"))):
            rows.append({"cve": cve, "mode": mode, "model": "" if mode == "rule" else "m", "status": "verified" if ok else "rejected",
                         "paths_before": p, "file_context_chars": fc, "graph_context_chars": gc})
    return rows


def test_kmeans_finds_easy_medium_hard():
    labels, sil, _ = ac.cluster(ac.features(_rows()), k=3)
    assert {labels[c] for c in ("E1", "E2", "E3")} == {"Easy"}
    assert {labels[c] for c in ("M1", "M2", "M3")} == {"Medium"}
    assert {labels[c] for c in ("H1", "H2", "H3")} == {"Hard"}
    assert sil > 0.5


def test_cluster_cli(tmp_path, capsys):
    jl = tmp_path / "runs.jsonl"
    jl.write_text("\n".join(json.dumps(r) for r in _rows()), encoding="utf-8")
    ac.main([str(jl), "--model", "m", "--out", str(tmp_path / "c.csv")])
    out = capsys.readouterr().out
    assert "only 9 CVEs" in out and "Easy" in out and "Hard" in out
    assert (tmp_path / "c.csv").read_text().startswith("cve,cluster")


def test_memory_holds_at_most_ten_and_never_evaluation_cves(tmp_path):
    m = ml.FixMemory(tmp_path / "mem.jsonl", embedder=ml.Embedder("tfidf"), exclude={"CVE-2018-17297"})
    assert m.add("CVE-2018-17297", "r", "CWE-022", "ctx", "", "+ fix") is False   # evaluation set: never stored
    for i in range(12):
        m.add(f"CVE-T{i}", f"repo{i}", "CWE-022", f"ctx {i}", "", "+ fix")
    assert len(m.load()) == ml.MEMORY_CAPACITY == 10
    assert m.add("CVE-T0", "repo0", "CWE-022", "ctx", "", "+ fix") is False       # no duplicates


def test_eval_set_is_the_paper_cve_list():
    ids = ml.read_cve_list(ml.EVAL_SET)
    assert "CVE-2018-1002201" in ids and all(i.startswith("CVE-") for i in ids)
