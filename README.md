# GraphPatch

**Graph-verified, multi-agent repair of security vulnerabilities in Java, with free and open-source tools.**

GraphPatch finds source-to-sink vulnerabilities with a taint graph and repairs them with an LLM Planner, Coder and Critic working in a loop. The same taint graph decides which code the agents see and acts as a **security gate**. A patch is accepted only if it compiles, keeps the existing tests passing **and** closes the vulnerable path. Final verdicts come from **held-out oracles** that no agent sees.

It runs with a local open-weight model (Qwen2.5-Coder through Ollama, no key, offline) or any OpenAI-compatible API (Gemini, Groq, OpenRouter, DeepSeek, OpenAI).

---

## 1. How it works

```
Java project ──► Taint graph ──► vulnerable paths ──► path-sliced context
                                                           │
             ┌─────────────────────────────────────────────┘
             ▼
        Planner ──► Coder ──► G1 compile ──► G2 tests ──► G3 taint graph ──► accepted
                      ▲                 (first failing gate)                    │
                      └──────── Critic ◄──────────────────────┘                 ▼
                                                                    held-out oracles: Verified / Plausible / Rejected
```

| Part | What it does | Code |
|---|---|---|
| Taint analysis | Inter-procedural flow from sources (request getters, archive entry names, parameters of vulnerable methods) to sinks (file, process, expression and output APIs). It follows data flow in a method, field flow in a class and call edges between methods, across up to 60 files of the same package. A sanitizer or guard such as `if (!f.getCanonicalPath().startsWith(base)) throw ...` cleans a variable from that line on. | `taint.py` (`TaintAnalysis`, `find_paths`) |
| Fixed-point propagation | Taint is propagated over all methods round after round until no new parameter, field, return value or finding is added. | `taint.py` (`TaintAnalysis.run`) |
| Source / sink catalogues | Sources, sinks, sanitizers and guards for CWE-22, 78, 79 and 94 are declared in YAML, not hard-coded. | `catalogues/*.yaml`, `catalogue.py` |
| Java parsing | Java source is parsed into an abstract syntax tree with `javalang`. | `javasrc.py`, `taint.py` |
| Path-sliced context | The agents see the vulnerable paths (at most 8), the imports, class header and fields, and the methods on those paths (at most 12). They do not see whole files. | `agents.py` (`graph_context`) |
| Planner, Coder, Critic | The Planner says where to break each path. The Coder writes SEARCH/REPLACE edits. The Critic is called only after a gate fails and explains what to change. | `agents.py`, `pipeline.py` |
| Edit application | Each SEARCH block is placed by exact match, then by whitespace-tolerant line match, then by similarity (a same-length window at least 90% similar by `difflib`, and clearly better than any rival). If one block fails, the whole patch is discarded. | `javasrc.py` (`apply_edits`, `_loose_find`, `_fuzzy_find`) |
| Gates | G1 compiles main and test sources. G2 runs the tests and compares them with a baseline run on the unpatched code, so only new failures count. G3 rebuilds the taint graph and requires every path to be gone. | `validator.py`, `build.py` (Maven or Gradle, Docker or local JDKs) |
| Held-out oracles | Graph-versus-fix comparison, proof-of-vulnerability tests and, optionally, CodeQL. These run once on the final patch. | `validator.py` (`final`), `codeql_oracle.py` |

### Machine-learning components

| Component | What it does | Code | Switch |
|---|---|---|---|
| **Constrained JSON decoding** | The Critic call sends `response_format={"type":"json_object"}`, so the model can only produce valid JSON. The reply is then checked against a schema (root cause plus 1 to 6 instructions with file, method, line, variable and action). If a server rejects the option, the call is sent once more without it. | `llm.py` (`chat(json_mode=True)`), `agents.py` (`parse_critique`) | on (`GP_LLM_JSON_MODE=0` turns it off) |
| **TF-IDF log analysis** | Each line of a compile or test log is one document. The top TF-IDF terms over the error lines, and the error lines that carry them, are given to the Critic before the full log. | `ml.py` (`log_keywords`, `augment_feedback`) | on in `full`/`seeded` (`--no-tfidf-log` turns it off) |
| **Fix memory (retrieval-augmented generation)** | Holds up to 10 verified fixes from a training split (CVEs outside `paper_cves.txt`), filled by a separate `--memory-build` run and only read during evaluation. Before the Planner runs, the new context is embedded and the *k* nearest stored fixes by cosine similarity (k-nearest neighbours) are added as examples. Embeddings come from `all-MiniLM-L6-v2` (384 dimensions, `sentence-transformers`); TF-IDF vectors are only a fallback, with a warning. Fixes from the same CVE or the same repository are never retrieved. | `ml.py` (`Embedder`, `FixMemory`) | on in `full`/`seeded` (default `results/fix_memory.jsonl`; `--no-memory`, `--memory PATH`, `--memory-k 3`, `--memory-build`) |
| **K-Means difficulty clusters** | CVEs are clustered into Easy, Medium and Hard from the number of taint paths and the code size (log-scaled, z-scored, k-means++ with 20 restarts). The script reports verified counts per cluster and system, and the silhouette score. | `analyze_clusters.py` | separate script |

### Graph analytics and statistics

| Component | What it does | Code |
|---|---|---|
| Program-wide taint graph | All paths are joined into one NetworkX directed graph. It reports reachable sinks, the files with the most tainted flow, choke points ranked by betweenness centrality (where one guard breaks the most paths), and the longest path. It exports GraphML, GEXF or JSON. | `graph.py` |
| Wilson score interval | 95% confidence interval for the share of verified fixes; suited to small samples. | `stats.py` (`wilson`) |
| Exact McNemar test | Paired comparison of two systems on the same CVEs (two-sided binomial test on the discordant pairs). | `stats.py` (`mcnemar_exact`) |
| Risk score | A 0–100 score built from a base per CWE plus points for the kind of input, a destructive sink and the path length. It is a triage aid, not a probability. | `scanner.py` (`risk`) |

### Repair modes

| Mode | Context | Gates in the loop | Agents |
|---|---|---|---|
| `full` | taint paths | compile + tests + taint graph | Planner, Coder, Critic |
| `seeded` | taint paths | compile + tests + taint graph | the rule patch is tried first; the agents run only if it fails a gate |
| `filectx` | whole files | compile + tests + taint graph | Planner, Coder, Critic |
| `nogate` | taint paths | compile + tests | Planner, Coder, Critic |
| `nograph` | whole files | compile + tests | Planner, Coder, Critic |
| `agent` | whole files | compile + tests | one Coder with raw feedback |
| `single` | whole files | none (one call) | one Coder |
| `rule` | taint paths | none | no model: a fixed containment check |
| `oracle` / `noop` | the developers' fix / no change | — | harness checks |

`--core-only` switches off the similarity edit placement, the JSON Critic and the stricter guard rules, leaving the core method only.

---

## 2. Install

You need Python 3.10+, git, JDK 8 and 17 with Maven (or Docker), and one model.

```bash
cd GraphPatch-Qwen-v3
python -m pip install -r graphpatch_v2/requirements.txt
python -m pip install sentence-transformers      # all-MiniLM-L6-v2 embeddings for the fix memory (in requirements.txt)
python -m pytest graphpatch_v2/tests
```

Model setup (pick one):

```bash
# Qwen2.5-Coder on Ollama (Ollama cuts prompts at 2,048 tokens by default; this makes a 24k-context copy)
ollama pull qwen2.5-coder:7b
printf 'FROM qwen2.5-coder:7b\nPARAMETER num_ctx 24576\n' > Modelfile.qwen
ollama create qwen2.5-coder-24k -f Modelfile.qwen

# or a hosted API (Gemini shown; GROQ_API_KEY, OPENROUTER_API_KEY, DEEPSEEK_API_KEY, OPENAI_API_KEY also work)
export GEMINI_API_KEY=...                       # PowerShell: $env:GEMINI_API_KEY = "..."
```

Optional, for the CodeQL oracle: download the CodeQL **bundle** from https://github.com/github/codeql-action/releases, unpack it, set `CODEQL=/path/to/codeql`, and check it with `python -m graphpatch_v2.codeql check`.

---

## 3. Run

**Benchmark CVEs** (CWE-Bench-Java, all CWE-22): `CVE-2022-25842 CVE-2018-1002201 CVE-2018-1002200 CVE-2018-1002202 CVE-2018-17297 CVE-2020-35460 CVE-2018-12036 CVE-2022-31194 CVE-2022-26049`

```bash
M="--provider ollama --model qwen2.5-coder-24k"     # or: --provider gemini --model <model-name> --rpm 5 --skip-done
CVES="--cves CVE-2022-25842 CVE-2018-1002201 CVE-2018-1002200 CVE-2018-1002202 CVE-2018-17297 CVE-2020-35460 CVE-2018-12036 CVE-2022-31194 CVE-2022-26049"

python -m graphpatch_v2.run_eval calibrate                       # how well the taint graph agrees with real fixes (no model)
python -m graphpatch_v2.run_eval run --mode noop   $CVES         # harness check: must never verify
python -m graphpatch_v2.run_eval run --mode oracle $CVES         # harness check: the developers' fix should verify
python -m graphpatch_v2.run_eval run --mode rule   $CVES         # rule-based fix (no model)
python -m graphpatch_v2.run_eval run --mode single  $M $CVES     # single prompt
python -m graphpatch_v2.run_eval run --mode nograph $M $CVES     # multi-agent, tests only
python -m graphpatch_v2.run_eval run --mode full    $M $CVES     # GraphPatch
python -m graphpatch_v2.run_eval run --mode seeded  $M $CVES     # GraphPatch + rule seed

# machine-learning options (add to any agent mode)
python -m graphpatch_v2.run_eval run --mode full $M --memory-build --cves <training CVEs>   # fill the fix memory first (never paper_cves.txt)
python -m graphpatch_v2.run_eval run --mode full $M $CVES                                      # TF-IDF and fix memory are on by default

# results
python -m graphpatch_v2.run_eval summarize
python -m graphpatch_v2.stats gp_runs/results/runs.jsonl --model <model-name>              # Wilson + McNemar
python -m graphpatch_v2.analyze_clusters gp_runs/results/runs.jsonl --model <model-name>   # K-Means clusters
```

Useful options: `--max-iters 3`, `--tests related` (faster), `--docker never`, `--codeql-oracle`, `--free-critic`, `--skip-done` (continue an interrupted set). Every run writes its prompts, replies, diffs, verdicts and critiques to `gp_runs/results/artifacts/<mode>/<cve>/`, and one record per run to `gp_runs/results/runs.jsonl`.

**Notes on the machine-learning options.** The memory is built once from training-split CVEs (`--memory-build`) and is read-only during evaluation, so results do not depend on the order of the evaluated CVEs. With few CVEs, K-Means groups the cases but is not a statistical test; the script prints a note below 15 CVEs.

### Web workspace

```bash
python -m graphpatch_v2.server        # open http://localhost:8000  (no Node or npm needed)
```

You can scan a project (ZIP upload, public GitHub URL, pasted Java, Python or JavaScript code, or the bundled sample), see each taint path as a graph, and repair it with the agents or the no-model rule fix while the steps stream live. You can also review the patch side by side and download the patched project. `frontend/dist/` is the prebuilt page and `frontend/src/` is its React source. To change it: `cd frontend && npm install && npm run dev`, then `npm run build`.

### Developer tools (no model, no key)

```bash
python -m graphpatch_v2.sarif <project> --out graphpatch.sarif   # SARIF 2.1.0 for code scanning in CI
python -m graphpatch_v2.graph <project> --out graph.graphml       # program-wide taint graph and choke points
python -m graphpatch_v2.attacktest <project> --out DIR           # JUnit attack tests for path traversal
python -m graphpatch_v2.deps <project>                           # Maven/Gradle dependencies against OSV
python -m graphpatch_v2.precommit --install                      # git pre-commit hook
```

Python (Flask/Django style) and JavaScript (Node/Express) projects are also scanned, with Tree-sitter (`polyglot.py`). The benchmark, the rule fix, the attack tests and the dependency check are Java only.

---


