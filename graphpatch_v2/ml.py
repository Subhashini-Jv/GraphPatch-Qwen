"""Machine-learning helpers for the repair loop, as described in the paper (Sections III-D and IV-E).
They are on by default in the GraphPatch modes (full, seeded); --no-tfidf-log and --no-memory turn them off.

  * TF-IDF key terms of a build or test log (``--tfidf-log``): each log line is one document, so terms that
    appear on a few error lines score high and boilerplate that appears on every line ([INFO], BUILD, ...)
    scores low. The Critic gets the top terms and the most informative error lines *in addition to* the log.
  * Fix memory (``--memory PATH``): holds at most MEMORY_CAPACITY (10) verified patches drawn from a training
    split, i.e. CVEs outside the evaluation set (paper_cves.txt). It is filled by a separate run with
    ``--memory-build`` and only read during evaluation runs. Every stored patch keeps the code context it fixed. Before the
    Planner runs, the code context of the new CVE is embedded and its k nearest stored fixes by cosine
    similarity (k-nearest neighbours) are given to the Planner as examples (retrieval-augmented generation).
    Embeddings come from a sentence-transformers model (default all-MiniLM-L6-v2, 384 dimensions) when that
    package is installed, otherwise from TF-IDF vectors. Fixes of the same CVE or of the same repository are
    never retrieved, so a benchmark run cannot see the answer to the CVE it is fixing.

K-Means clustering of CVE difficulty is a separate analysis script: ``analyze_clusters.py``.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

# ------------------------------------------------------------------ TF-IDF on build / test logs

# identifiers, dotted names (org.apache.Foo), words; at least 3 characters, not purely numeric
TOKEN = r"(?u)\b[A-Za-z_][A-Za-z0-9_.$]{2,}\b"
ERROR_LINE = re.compile(r"\[ERROR\]|\berror\b|Exception|FAIL|cannot find symbol|expected|incompatible|"
                        r"Caused by|AssertionError|\bat line\b|\.java:\[?\d+", re.I)
LOG_STOP = {"info", "error", "warning", "warn", "build", "maven", "plugin", "org.apache.maven", "the", "and", "for",
            "with", "from", "this", "that", "was", "are", "see", "full", "stack", "trace", "help", "run", "using",
            "re", "mvn", "switch", "debug", "logging", "more", "about", "following", "articles", "possible",
            "solutions", "please", "read", "http", "https", "cwiki.apache.org", "confluence", "display"}


@dataclass
class LogSummary:
    keywords: list[str]
    lines: list[str]

    def render(self) -> str:
        if not self.keywords:
            return ""
        out = ["KEY TERMS IN THE LOG (TF-IDF over log lines): " + ", ".join(self.keywords)]
        if self.lines:
            out.append("MOST INFORMATIVE ERROR LINES:")
            out += [f"  {l}" for l in self.lines]
        return "\n".join(out)


def log_keywords(log: str, top: int = 5, top_lines: int = 5) -> LogSummary:
    """Top TF-IDF terms of a build/test log, scored over the error lines, and the error lines that carry them."""
    from sklearn.feature_extraction.text import TfidfVectorizer

    lines = [l.strip() for l in (log or "").splitlines() if l.strip()]
    if len(lines) < 2:
        return LogSummary([], [])
    vec = TfidfVectorizer(token_pattern=TOKEN, lowercase=True, stop_words=sorted(LOG_STOP), sublinear_tf=True)
    try:
        X = vec.fit_transform(lines)              # one document per log line
    except ValueError:                            # only stop words
        return LogSummary([], [])
    terms = vec.get_feature_names_out()
    err = [i for i, l in enumerate(lines) if ERROR_LINE.search(l)] or list(range(len(lines)))
    scores = X[err].sum(axis=0).A1              # importance of each term over the error lines
    order = scores.argsort()[::-1]                # highest score first (not alphabetical)
    keywords = [terms[i] for i in order[:top] if scores[i] > 0]
    # a line is informative when its own TF-IDF vector points the same way as the log's term importance
    line_score = {i: float(X[i].dot(scores)[0]) for i in err}
    best = sorted((i for i in err if line_score[i] > 0), key=lambda i: -line_score[i])[:top_lines]
    return LogSummary(keywords, [lines[i][:300] for i in sorted(best)])


def augment_feedback(feedback: str, stage: str) -> tuple[str, list[str]]:
    """Prepend the TF-IDF summary to compile and test feedback. The full feedback is kept after it."""
    if not (stage == "compile" or str(stage).startswith("test")) or not feedback:
        return feedback, []
    s = log_keywords(feedback)
    head = s.render()
    return (head + "\n\nFULL VALIDATOR OUTPUT:\n" + feedback if head else feedback), s.keywords


# ------------------------------------------------------------------ embeddings

DEFAULT_EMBED_MODEL = "all-MiniLM-L6-v2"
MEMORY_CAPACITY = 10      # the paper's memory holds up to 10 verified patches from the training split


class Embedder:
    """sentence-transformers when installed (GP_EMBED_MODEL, default all-MiniLM-L6-v2), else TF-IDF vectors.
    Set GP_EMBED_MODEL=tfidf to force TF-IDF."""

    def __init__(self, model: str | None = None):
        self.name = model or os.environ.get("GP_EMBED_MODEL", DEFAULT_EMBED_MODEL)
        self._st = None
        if self.name != "tfidf":
            try:
                from sentence_transformers import SentenceTransformer
                self._st = SentenceTransformer(self.name)
            except Exception as e:                # not installed or model not downloadable: fall back
                self._st = None
                import sys
                print(f"warning: sentence-transformers model {self.name!r} unavailable ({e.__class__.__name__}); "
                      "the fix memory falls back to TF-IDF vectors, which differs from the paper", file=sys.stderr)
        self.kind = f"sentence-transformers:{self.name}" if self._st is not None else "tfidf"

    def embed(self, texts: list[str]):
        """Vectors for texts, one row each (the vectorizer is fit on exactly these texts in TF-IDF mode)."""
        if self._st is not None:
            return self._st.encode(texts, normalize_embeddings=True)
        from sklearn.feature_extraction.text import TfidfVectorizer
        return TfidfVectorizer(token_pattern=TOKEN, sublinear_tf=True).fit_transform(texts)


# ------------------------------------------------------------------ fix memory (KNN + cosine similarity)

@dataclass
class Memory:
    cve: str
    repo: str
    cwe: str
    context: str
    plan: str
    diff: str
    similarity: float = 0.0


class FixMemory:
    """Verified fixes in a JSON-lines file, retrieved by k-nearest neighbours under cosine distance."""

    def __init__(self, path: Path, embedder: Embedder | None = None, max_context: int = 6000,
                 capacity: int = MEMORY_CAPACITY, exclude: set[str] | None = None):
        self.path = Path(path)
        self.max_context = max_context
        self.capacity = capacity
        # CVEs of the evaluation set: never stored, so the memory only holds the training split
        self.exclude = {c.upper() for c in (exclude or set())}
        self._embedder = embedder

    @property
    def embedder(self) -> Embedder:
        if self._embedder is None:
            self._embedder = Embedder()
        return self._embedder

    def load(self) -> list[Memory]:
        if not self.path.exists():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                d = json.loads(line)
                out.append(Memory(d["cve"], d.get("repo", ""), d.get("cwe", ""), d["context"], d.get("plan", ""), d["diff"]))
            except (json.JSONDecodeError, KeyError):
                continue
        return out

    def add(self, cve: str, repo: str, cwe: str, context: str, plan: str, diff: str, **extra) -> bool:
        """Store a verified fix. Returns False (and stores nothing) for an empty diff, an evaluation-set CVE,
        a CVE already stored, or a full memory."""
        if not diff.strip() or cve.upper() in self.exclude:
            return False
        stored = self.load()
        if len(stored) >= self.capacity or any(m.cve == cve for m in stored):
            return False
        self.path.parent.mkdir(parents=True, exist_ok=True)
        rec = {"cve": cve, "repo": repo, "cwe": cwe, "context": context[:self.max_context], "plan": plan[:3000],
               "diff": diff[:6000], **extra}
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")
        return True

    def query(self, context: str, cve: str, repo: str, cwe: str | None = None, k: int = 3,
              min_similarity: float = 0.2) -> list[Memory]:
        """The k stored fixes most similar to context. Never the same CVE or repository (no answer leakage);
        only the same CWE when cwe is given."""
        from sklearn.neighbors import NearestNeighbors

        pool = [m for m in self.load()[:self.capacity] if m.cve != cve and (not repo or m.repo != repo) and (not cwe or m.cwe == cwe)]
        if not pool or k <= 0:
            return []
        X = self.embedder.embed([m.context for m in pool] + [context[:self.max_context]])
        nn = NearestNeighbors(n_neighbors=min(k, len(pool)), metric="cosine", algorithm="brute").fit(X[:-1])
        dist, idx = nn.kneighbors(X[-1:])
        out = []
        for d, i in zip(dist[0], idx[0]):
            sim = 1.0 - float(d)
            if sim >= min_similarity:
                m = pool[int(i)]
                m.similarity = round(sim, 3)
                out.append(m)
        return out


def render_examples(mem: list[Memory]) -> str:
    if not mem:
        return ""
    parts = ["SIMILAR VERIFIED FIXES FROM OTHER PROJECTS (retrieved by cosine similarity; the code differs, use them "
             "only as examples of how such a path was broken):"]
    for i, m in enumerate(mem, 1):
        parts.append(f"--- example {i}: {m.cve} ({m.cwe}), similarity {m.similarity:.2f} ---\n{m.diff[:2500]}")
    return "\n".join(parts)


def read_cve_list(path: Path) -> set[str]:
    """CVE ids from a file with one id per line (comments after #), e.g. paper_cves.txt."""
    p = Path(path)
    if not p.exists():
        return set()
    return {l.split("#")[0].strip().upper() for l in p.read_text(encoding="utf-8", errors="replace").splitlines()
            if l.split("#")[0].strip()}


EVAL_SET = Path(__file__).with_name("paper_cves.txt")
