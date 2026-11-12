# GraphPatch (enhanced project)

**A zero-cost, graph-verified multi-agent framework for automated vulnerability remediation (Java).**

This is the code for the paper *"GraphPatch: A Zero-Cost, Graph-Verified Multi-Agent Framework for Automated Vulnerability Remediation"* (M. Sarmila, Srikanth M, Tharshana S, Subhashini J). Everything the paper describes is implemented (Section 1). On top of that, the project adds the improvements the paper lists as future work and threats to validity (Section 2). The paper itself is unchanged.

An LLM Planner, Coder and Critic repair a vulnerability in a loop. One source-to-sink **taint graph** chooses the code the agents see and acts as a **security gate**: a patch is accepted only when it compiles, keeps the tests passing **and** closes the vulnerable path. Final verdicts use **held-out oracles** that no agent sees.

---

## 1. Paper → code: where every part of the paper is

### Approach (Section III)

| Paper | What it is | Code |
|---|---|---|
| III-A, Eq. (1) | Vulnerable paths P(R) = flows from sources to sinks that pass no sanitizer | `taint.py`: `find_paths()`, `TargetSpec`; per-CWE catalogues declared in `catalogues/java.yaml` (loaded by `catalogue.py`) |
| III-B | Taint graph: data flow in a method, field flow in a class, call edges, fixed-point propagation, up to 60 same-package files, guards clean variables | `taint.py`: `TaintAnalysis.run()` (fixed point), `_stmt()`, `_expr()`, `_call()`, `same_package_files(limit=60)` |
| III-C | Path-sliced context: at most 8 paths, imports/header/fields, at most 12 methods | `agents.py`: `graph_context()` (whole-file baseline: `file_context()`) |
| III-D | Planner, Coder, Critic, Validator | `agents.py`: `planner_prompt()`, `coder_prompt()`, `critic_prompt()`; `validator.py`: `Validator` |
| III-D | SEARCH/REPLACE edits, exact and whitespace-tolerant matching, near-miss feedback, whole patch discarded on a failed block | `javasrc.py`: `parse_edits()`, `apply_edits()`, `_loose_find()`, `_near_miss()` |
| **Algorithm 1** | Graph-verified repair loop: G1 compile → G2 tests vs. baseline → G3 security; first failure goes to the Critic; up to K iterations; no fallback to an earlier candidate | `pipeline.py`: `run_cve()` (the `for it in range(1, cfg.max_iters + 1)` loop); gates in `validator.py`: `Validator.check()`, `loop_accepts()`; Maven/Gradle, Docker or local JDKs in `build.py` |
| III-E | Developer tooling: SARIF 2.1.0 export with CI workflow, 0–100 risk score, pre-commit hook, JUnit attack tests, OSV dependency check, FastAPI web UI | `sarif.py`, `scanner.py: risk()`, `precommit.py`, `attacktest.py`, `deps.py`, `server.py` + `web/`, CI files in `github/` |

### Experimental setup (Section IV)

| Paper | What it is | Code |
|---|---|---|
| IV-A | CWE-Bench-Java, perfect fault localization | `dataset.py` (clones the benchmark), `workspace.py` (checkouts) |
| IV-B, Table I | Calibration of the gate on vulnerable vs. fixed code | `calibrate.py`; `python -m graphpatch_v2.run_eval calibrate`; result in `sample_results/calibration.csv` |
| IV-B | Harness checks (no change must never verify, developers' fix should) | modes `noop` and `oracle` in `pipeline.py`; result in `sample_results/sanity_noop_oracle.csv` |
| IV-B | Vul4J calibration | `vul4j_bench.py`, `benchmarks/` |
| IV-C | Held-out oracles: graph-versus-fix, PoV tests, verdicts Verified / Plausible / Rejected | `validator.py`: `prepare_graph_reference()`, `prepare_pov()`, `final()` |
| IV-D | B0 rule, B1 single prompt, B3 multi-agent tests only, GraphPatch (K = 3) | modes `rule`, `single`, `nograph`, `full` (table at the top of `pipeline.py`); extra ablations `filectx`, `nogate`, `agent` |
| IV-E, Table II | One OpenAI-compatible client: Gemini free tier at temperature 0 (5 req/min, resumes next day), or Qwen2.5-Coder via Ollama | `llm.py` (`--provider`, `--model`, `--rpm`), `run_eval.py --skip-done`, `daily_run.ps1` |

### Results (Section V)

| Paper | Code |
|---|---|
| Tables III, IV | `python -m graphpatch_v2.run_eval summarize`; LaTeX numbers via `fill_results.py` |
| V-B Wilson 95 % intervals and exact McNemar tests | `stats.py` (`python -m graphpatch_v2.stats ...`); `tests/test_stats.py` reproduces the paper's 35–88 %, 27–81 %, p = 0.25 and p = 1.0 from Table III |
| V-C Security gate stopping test-passing patches | per-iteration `verdict_N.json` in the run artifacts (`stage: graph`) |
| V-D Context size and tokens | recorded per run in `runs.jsonl` (`graph_context_chars`, `file_context_chars`, `prompt_tokens`, ...) |

**Everything the paper describes is implemented.** To reproduce the paper's runs exactly, add `--paper-mode` to `run_eval run` (it switches off every enhancement of Section 2).

## 2. Enhancements beyond the paper

These come from the paper's own Section VI-C (Threats to Validity) and Section VII (Future Work). They are on by default; `--paper-mode` turns them all off (the last two change no result, so they need no switch).

| Enhancement | Why (paper) | Code | Switch |
|---|---|---|---|
| **Edit-distance SEARCH placement**: when exact and whitespace-tolerant matching fail, a SEARCH block is placed at the same-length window that is ≥ 90 % similar (difflib ratio) and 5 points better than any rival; never for one-line, ambiguous or different-length blocks | VII: "Edit-distance matching of SEARCH blocks would recover the edit-format failures seen on CVE-2022-31194" | `javasrc.py`: `_fuzzy_find()` | `--paper-mode` |
| **Structured Critic**: the Critic is asked for JSON (root cause + up to 6 instructions with file, method, line, variable, action); the harness validates it, measures how many surviving paths it addresses, and falls back to the raw text if it is not valid JSON | VII: "a Critic constrained to structured JSON output would make its feedback machine-checkable" | `agents.py`: `parse_critique()`, `render_critique()`, `critique_coverage()`; `pipeline.py: _critic()` | `--free-critic` or `--paper-mode` |
| **Stricter guard recognition**: `equals` / `contains` / `indexOf` / `matches` count as a guard only as a negated allow-list or a block-list with a dangerous literal, so `if (name.equals("")) throw` no longer clears a path | VI-C: "a check that tests nothing useful ... is enough to clear a path" | `taint.py`: `_meaningful()` | `--paper-mode` |
| **Rule-seeded mode `seeded`**: the B0 rule's patch is candidate 1; the agents take over only if it fails a gate | VI-A: "Seeding the Coder with the rule's patch as its first candidate is a natural combination" | `pipeline.py` (mode `seeded`) | separate mode |
| **CodeQL held-out oracle**: CodeQL runs on the vulnerable code, the developers' fix and the final patch; a patch must remove what the fix removes and add no new alert | VI-C: "The graph-versus-fix oracle uses the same query as gate G3, which favors GraphPatch"; VII: sound dataflow analysis | `codeql_oracle.py` | `--codeql-oracle` |
| **Statistics of Section V-B**: Wilson intervals and exact McNemar tests | V-B | `stats.py` (reproduces 35–88 %, 27–81 %, p = 0.25 and 1.0) | — |
| **Declarative language catalogue**: every Java source, sink, sanitizer and guard of the taint graph is declared in a YAML file instead of being hard-coded; a test checks it is identical to the former in-code catalogue, so all results are unchanged | VII: "declarative per-language catalogues of sources, sinks and guards" | `catalogues/java.yaml`, `catalogue.py` | always on (no behaviour change) |
| **NetworkX program graph**: all taint paths of a project are joined into one NetworkX `DiGraph` (shared statements are one node) to report reachable sinks, hot files and choke points (betweenness centrality: where one guard breaks the most paths), and to export GraphML / GEXF / JSON. The taint propagation itself is still the fixed-point analysis in `taint.py` | III-B (code graph) | `graph.py`; `python -m graphpatch_v2.graph <project> --out g.graphml`; web: `/api/scan/{id}/graph` | always on (reporting only) |
| **Python and JavaScript front end**: Python (Flask/Django-style) and JavaScript (Node/Express) projects are scanned with Tree-sitter, driven by `catalogues/python.yaml` and `catalogues/javascript.yaml` (sources, sinks for CWE-22, 78, 79 and 94, sanitizers, guards). The analysis is per function (plus module level) with guard and sanitizer recognition; results feed the same NetworkX graph and the same Planner/Coder/Critic repair loop in the web app, and a patch is checked by re-parsing it with Tree-sitter and re-running the taint graph. Not evaluated in the paper: the benchmark, the B0 rule fix, the attack tests and the library (OSV) checks stay Java-only | VII: "A Tree-sitter front end would let one graph serve several languages" | `polyglot.py`, `catalogues/python.yaml`, `catalogues/javascript.yaml`; `scanner.py`, `server.py` | always on for `.py` / `.js` files (Java analysis unchanged) |

The calibration of Table I was re-run with the stricter guards on all 120 CVEs: every count is unchanged. Results of the enhanced modes have not been measured with a model yet; they are not part of the paper.

---

## 3. Install

Requirements: Python 3.10+, git, JDK 8 and 17 + Maven (or Docker), and one model:
a free Gemini API key (https://aistudio.google.com) **or** Ollama with Qwen2.5-Coder (no key, runs offline).

```bash
cd GraphPatch-Qwen-v3
python -m pip install -r graphpatch_v2/requirements.txt
python -m pytest graphpatch_v2/tests          # 120 passed, 1 skipped
```

Model setup (pick one):

```bash
# Gemini, free tier
export GEMINI_API_KEY=...                       # PowerShell: $env:GEMINI_API_KEY = "..."

# Qwen2.5-Coder on Ollama (Ollama cuts prompts at 2,048 tokens by default; this makes a 24k copy)
ollama pull qwen2.5-coder:7b
printf 'FROM qwen2.5-coder:7b\nPARAMETER num_ctx 24576\n' > Modelfile.qwen
ollama create qwen2.5-coder-24k -f Modelfile.qwen
```

Optional, for the CodeQL oracle: download the CodeQL **bundle** from https://github.com/github/codeql-action/releases, unpack it, set `CODEQL=/path/to/codeql`, then check with `python -m graphpatch_v2.codeql check`.

---

## 4. Run

The 9 paper CVEs: `CVE-2022-25842 CVE-2018-1002201 CVE-2018-1002200 CVE-2018-1002202 CVE-2018-17297 CVE-2020-35460 CVE-2018-12036 CVE-2022-31194 CVE-2022-26049` (also in `graphpatch_v2/paper_cves.txt`).

**Everything in one go (Qwen, local):**

```bash
./run_qwen.sh                    # Windows: .\run_qwen.ps1
GP_CODEQL=1 ./run_qwen.sh        # Windows: .\run_qwen.ps1 -CodeQL     (also judge with CodeQL)
GP_PAPER_MODE=1 ./run_qwen.sh    # Windows: .\run_qwen.ps1 -PaperMode  (exactly as in the paper)
```

**Step by step (any model):**

```bash
M="--provider gemini --model <gemini-model-name> --rpm 5 --skip-done"   # or: --provider ollama --model qwen2.5-coder-24k
CVES="--cves-file graphpatch_v2/paper_cves.txt"

python -m graphpatch_v2.run_eval calibrate                                # Table I (no model)
python -m graphpatch_v2.run_eval run --mode noop   $CVES                  # harness check: must never verify
python -m graphpatch_v2.run_eval run --mode oracle $CVES                  # harness check: developers' fix
python -m graphpatch_v2.run_eval run --mode rule   $CVES                  # B0 (no model)
python -m graphpatch_v2.run_eval run --mode single  $M $CVES              # B1
python -m graphpatch_v2.run_eval run --mode nograph $M $CVES              # B3
python -m graphpatch_v2.run_eval run --mode full    $M $CVES              # GraphPatch
python -m graphpatch_v2.run_eval run --mode seeded  $M $CVES              # enhancement: rule-seeded (not in the paper)
python -m graphpatch_v2.run_eval run --mode filectx $M $CVES              # ablation: whole files
python -m graphpatch_v2.run_eval run --mode nogate  $M $CVES              # ablation: no security gate
# add --paper-mode to reproduce the paper exactly; add --codeql-oracle to also judge with CodeQL

python -m graphpatch_v2.run_eval summarize                                # Tables III and IV
python -m graphpatch_v2.stats gp_runs/results/runs.jsonl --model <model-name>   # Wilson + McNemar
python fill_results.py gp_runs/results/runs.jsonl --model <model-name> > paper/results.tex
```

On the free Gemini tier (20 requests a day) a full set takes several days; `--skip-done` continues where the last run stopped, and `graphpatch_v2/daily_run.ps1` does this automatically. Useful options: `--tests related` (faster), `--max-iters 3`, `--docker never`, `--free-critic` (the original free-text Critic).

**Web workspace (`frontend/`, included in this zip and already built):**

```bash
python -m graphpatch_v2.server        # open http://localhost:8000  (no Node or npm needed)
```

The zip contains the `frontend/` folder: `frontend/dist/` is the ready-built page the server shows at `/`, and `frontend/src/` is its React source. In the browser you can scan a project (ZIP upload, public GitHub URL, pasted Java, Python or JavaScript code, or the bundled sample), see each taint path as a graph, repair it with the agents or the no-model rule fix while the steps stream live, review the patch side by side, download the patched project, and see benchmark verdicts. Repair with agents needs the model variables of Section 3 set before the server starts; the rule fix needs nothing (it handles Java path traversal only).

- Node.js and npm are only needed to change the frontend: `cd frontend && npm install && npm run dev` (details in `frontend/README.md`), then `npm run build` to update `frontend/dist/`.
- If `frontend/dist/` is missing, the server still starts and shows the original one-page UI instead; that UI is always available at `/classic`.

**Developer tools (no model, no key):**

```bash
python -m graphpatch_v2.sarif <project> --out graphpatch.sarif   # SARIF 2.1.0 for GitHub code scanning
python -m graphpatch_v2.attacktest <project> --out DIR      # JUnit attack tests for path traversal
python -m graphpatch_v2.deps <project>                      # Maven/Gradle dependencies against OSV
python -m graphpatch_v2.precommit --install                 # git pre-commit hook
```

Every run writes its prompts, replies, diffs, verdicts and critiques to `gp_runs/results/artifacts/<mode>/<cve>/`.

---

## 5. Folder layout

```
README.md               this file
RUN_QWEN.md             how to fill the paper's numbers with Qwen
run_qwen.sh / .ps1      run every mode on the 9 paper CVEs and write paper/results.tex
fill_results.py         runs.jsonl -> LaTeX numbers for the paper
paper/graphpatch.tex    LaTeX version of the paper with Qwen placeholders (numbers read from results.tex), unchanged
frontend/               React web workspace (prebuilt in frontend/dist; served by graphpatch_v2.server)
graphpatch_v2/          the framework (see Section 1 for each file)
  CHANGES_v3.md         what v3 adds and why
  README.md             detailed technical notes (Vul4J, CodeQL calibration, CI)
  catalogues/*.yaml     sources, sinks, sanitizers and guards for Java, Python and JavaScript (declarative)
  polyglot.py           Tree-sitter taint analysis for Python and JavaScript
  tests/                120 unit and end-to-end tests
  sample_results/       calibration and harness-check results
```
