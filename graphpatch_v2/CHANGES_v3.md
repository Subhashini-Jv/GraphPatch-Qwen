# GraphPatch v3: enhancements from the paper's Future Work and Threats to Validity

| # | Enhancement | Where | Paper section it answers |
|---|---|---|---|
| 1 | **Edit-distance SEARCH placement.** After exact and whitespace-tolerant matching fail, a SEARCH block is placed at the file window with the same number of lines that is at least 90% similar (difflib) and at least 5 points better than any non-overlapping rival. Never placed by similarity: single-line blocks, ambiguous blocks, or windows of a different length (that would delete lines the model never wrote). | `javasrc.py` (`_fuzzy_find`, `apply_edits(fuzzy_log=)`) | Future Work: "edit-distance matching of SEARCH blocks would recover the edit-format failures seen on CVE-2022-31194" |
| 2 | **Structured (JSON) Critic.** The Critic returns `{"root_cause", "instructions": [{file, method, line, variable, action}]}`; the harness validates it, measures which surviving taint paths it addresses (`critic_path_coverage`), and renders it for the Coder. Invalid JSON is passed on as text and counted (`critic_invalid`), so a run never stops on it. `--free-critic` restores the original free-text Critic. The web UI uses the same format. | `agents.py` (`CRITIC_FORMAT`, `parse_critique`, `render_critique`, `critique_coverage`), `pipeline.py` (`_critic`), `server.py` | Future Work: "a Critic constrained to structured JSON output would make its feedback machine-checkable" |
| 3 | **Stricter guard recognition.** `equals`, `contains`, `indexOf`, `matches` count as a guard only as a negated allow-list (`!ALLOWED.contains(x)`) or a block-list with a literal that matters for the CWE (`x.contains("..")` for CWE-22, shell metacharacters for CWE-78, `<`/`>` for CWE-79, ...). `if (name.equals("")) throw` no longer clears a path. | `taint.py` (`WEAK_GUARD_CALLS`, `DANGEROUS_LITERAL`, `_meaningful`) | Threats to Validity: "a check that tests nothing useful, such as `if (name.equals("")) throw ...`, is enough to clear a path" |
| 4 | **`seeded` mode (GraphPatch + Rule).** The B0 rule's patch is candidate 1 and goes through all three gates; only if it fails do the Critic, Planner and Coder run, starting from the rule's patch. It counts against the budget K. A CVE the rule closes costs no model call. | `pipeline.py` (`seeded` in `LOOP_MODES`), `agents.coder_prompt(prev_by_rule=)` | Discussion: "Seeding the Coder with the rule's patch as its first candidate is a natural combination" |
| 5 | **CodeQL as an independent held-out oracle.** `run_eval run ... --codeql-oracle [PATH]` runs CodeQL's Java security queries on the vulnerable code, the developers' fix and the final patch. The patch must remove every alert the fix removes and add none that neither the vulnerable code nor the fix has (alerts are keyed by code text, so rewriting only the sink line cannot hide an open path). A CodeQL failure never stops a run (`codeql_ok` = null, `codeql_error` recorded). `python -m graphpatch_v2.codeql judgeable [--only-new]` lists the CVEs CodeQL can judge, from the CodeQL calibration, for `--cves-file`. | `codeql_oracle.py`, `validator.py` (`run_codeql`), `vul4j_bench.py`, `run_eval.py` | Threats to Validity: "The graph-versus-fix oracle uses the same query as gate G3, which favors GraphPatch"; Future Work: Joern/sound dataflow |
| 6 | **Constrained JSON decoding for the Critic.** The Critic call now sends `response_format={"type": "json_object"}` (OpenAI-compatible; accepted by Gemini, Ollama, Groq, OpenAI, DeepSeek, OpenRouter), so the server only lets the model emit tokens that keep the reply a valid JSON object. Planner and Coder calls are unchanged. The schema check in `parse_critique` still runs (JSON mode guarantees valid JSON, not the schema). A server that rejects the parameter gets the same call again without it, once. Each call logs `json_mode`; each run row counts `critic_constrained`. `GP_LLM_JSON_MODE=0` turns it off; `--free-critic` / `--paper-mode` never use it. | `llm.py` (`chat(json_mode=)`), `pipeline.py` (`_ask`, `_critic`), `server.py`, `tests/test_llm_json_mode.py` | Future Work: "a Critic constrained to structured JSON output" (v3 #2 asked for JSON in the prompt; this constrains the decoding itself) |
| 7 | **TF-IDF key terms of build and test logs** (`--tfidf-log`, off by default). Each log line is one document, so terms on a few error lines score high and boilerplate on every line scores low. Terms are ranked by their TF-IDF over the error lines (not alphabetically), and the error lines most aligned with those terms are picked. The Critic gets both *before* the full log, which it still receives. Run rows record `tfidf_keywords`. | `ml.py` (`log_keywords`, `augment_feedback`), `pipeline.py` | — (new) |
| 8 | **Fix memory: embeddings + k-nearest neighbours under cosine similarity** (`--memory PATH`, `--memory-k 3`, off by default). Each verified patch from a loop mode is stored with its path-sliced context. Before the Planner runs, the new CVE's context is embedded and the k most similar stored fixes (cosine similarity ≥ 0.2, same CWE) are added to the Planner's context as examples (RAG). Embeddings: sentence-transformers `all-MiniLM-L6-v2` (384-d) if installed (`GP_EMBED_MODEL`), else TF-IDF vectors. **Leakage guard:** fixes of the same CVE or the same repository are never retrieved. Run rows record `memory_hits`, `memory_similarity`, `memory_embedder`, `memory_stored`. Results depend on the order CVEs are run in, so report the order (or use a memory built from a separate set of CVEs). | `ml.py` (`Embedder`, `FixMemory`, `render_examples`), `pipeline.py`, `run_eval.py` | — (new) |
| 9 | **K-Means difficulty clusters** for the Discussion. Features per CVE from the run records (taint paths, vulnerable-file size, path-context size), log-scaled and z-scored; K-Means (k=3, 20 restarts, fixed seed); clusters named Easy/Medium/Hard by centroid; silhouette score printed; verified counts per cluster and system. Descriptive only: with 9 CVEs it groups cases, it is not a test, and the script says so. | `analyze_clusters.py` (`python -m graphpatch_v2.analyze_clusters runs.jsonl --model <m>`) | Discussion: "What a Rule Can Already Do" |

## Results bookkeeping

* Every row now carries `gp: 3` and `critic: json|free`. `--skip-done` only skips rows with `gp >= 3`, so
  runs made with v2 are repeated instead of being mixed with v3 results.
* New row fields: `fuzzy_edits`, `critic_calls`, `critic_invalid`, `critic_path_coverage`, `seeded`,
  `codeql_ok`, `codeql_paths_removed_by_real_fix`, `codeql_error`. Per-iteration files: `critique_N.json`, `fuzzy_N.txt`.
* `fill_results.py` writes macros for the `seeded` and `rule` modes and the new metrics
  (`@fuzzy`, `@critcalls`, `@critvalid`, `@critcov`, `@cqjudged`, `@cqok`, `seeded@rulealone`, `seeded@rulealoneV`).
* The paper is unchanged. `run_eval run --paper-mode` switches every enhancement off (free-text Critic, exact and
  whitespace-tolerant matching only, the paper's guard rules) to reproduce the paper's runs; such rows carry
  `paper_mode: true`, and `fill_results.py --paper-mode` uses only them.

## Not re-measured here

* **Table I (calibration) was re-measured with v3** on all 120 CWE-Bench-Java CVEs (2026-11-12, Linux,
  no model): every count is unchanged (33 / 9 / 15). The only per-CVE difference is keycloak CVE-2022-4361,
  where 4 paths are now reported on both the vulnerable and the fixed code instead of 2 (a value check that
  restricts nothing no longer clears them); it was not judgeable before and is not now.
  `sample_results/calibration.csv` holds the v3 run.
* The CodeQL oracle is tested with CodeQL faked; `analyze` and `parse_sarif` are the existing, separately
  tested functions from `codeql.py`. Run `python -m graphpatch_v2.codeql check` once before using it.

## Tests

`python -m pytest graphpatch_v2/tests` : 120 passed, 1 skipped (75 before v3). New: `test_critic.py`, paper-mode tests, `test_stats.py` (reproduces the paper's Wilson and McNemar numbers),
`test_codeql_oracle.py`, fuzzy-edit tests in `test_edits.py`, guard tests in `test_taint.py`, and end-to-end
`seeded` / JSON-Critic / CodeQL-oracle runs in `test_vul4j.py` (fake Vul4J, fake model, fake CodeQL).

## Web workspace (React frontend)

`frontend/` is a React + Vite workspace with nine pages (overview, repositories, scanner, taint graph,
agents, patch review, validation, reports, settings), all on live backend data. `python -m graphpatch_v2.server`
serves the prebuilt `frontend/dist` at `/`; the old one-page UI stays at `/classic`. New endpoints:
`GET /api/scans`, `GET /api/scan/{id}/fix`, `GET /api/scan/{id}/source`. The paper's method and the
benchmark harness are unchanged by this.

## Declarative catalogue and NetworkX graph

- `catalogues/java.yaml` + `catalogue.py`: the Java sources, sinks, sanitizers and guards are data, not code.
  `tests/test_catalogue.py` checks the loaded values equal the former hard-coded ones, so no result changes.
- `graph.py`: joins every taint path into one NetworkX `DiGraph`; reachable sinks before/after a repair,
  hot files, choke points (betweenness centrality), GraphML/GEXF/JSON export. The taint propagation is unchanged.
  Web: `GET /api/scan/{id}/graph`, `GET /api/scan/{id}/taint-graph.graphml`; shown on the Taint Graph page.
- New requirements: `networkx`, `PyYAML`.

## Python and JavaScript (Tree-sitter)

Section VII names a Tree-sitter front end as future work; this adds one for Python and JavaScript.

- `polyglot.py`: Tree-sitter parsing and a per-function taint analysis (sources, assignments, destructuring,
  loops over archive entries, sanitizers, `if <check>: raise/return/throw` guards, sinks by call or by property
  such as `innerHTML`). Findings use the same `Finding` type as Java, so the NetworkX graph, the web pages and
  the Planner/Coder/Critic loop work unchanged; a patch is re-parsed with Tree-sitter and re-scanned (gate G3).
- `catalogues/python.yaml`, `catalogues/javascript.yaml`: sources (Flask/Django request objects, Express
  `req.*`, archives), sinks for CWE-22 (path traversal), CWE-78 (OS command), CWE-79 (XSS) and CWE-94 (code injection), sanitizers and guards.
- `scanner.py` scans `.java`, `.py`, `.js/.mjs/.cjs` files; the web app shows per-language file counts and
  the paste box detects the language.
- Java analysis is unchanged (catalogue snapshot test). The benchmark, the B0 rule fix, the attack tests and the
  OSV library checks stay Java-only, and the new languages are not evaluated in the paper.
- Tests: `test_polyglot.py` (Flask and Express samples, guarded routes produce no finding), a scripted-model
  repair of a Python project in `test_server.py`, and language detection of pasted code.
- New requirements: `tree-sitter`, `tree-sitter-python`, `tree-sitter-javascript` (prebuilt wheels).

## v3.4: code aligned with the paper (ICRCICN 2027 revision)

* TF-IDF log distillation and the fix memory are **on by default** in the GraphPatch modes (`full`, `seeded`) and
  off in the baselines and ablations. `--no-tfidf-log` / `--no-memory` turn them off. (Items 7 and 8 above said
  "off by default"; that no longer holds.)
* The fix memory holds at most **10** verified patches drawn from a **training split**: it is filled by a separate
  `--memory-build` run, never stores a CVE listed in `paper_cves.txt`, and is read-only during evaluation runs.
  The default path is `results/fix_memory.jsonl`. If it is empty, GraphPatch runs without retrieved examples.
* `sentence-transformers` (all-MiniLM-L6-v2) is now a requirement; the TF-IDF fallback prints a warning.
* Run rows record `tfidf_log`, `memory` and `memory_build`, so the configuration behind every result is on file.
* `--paper-mode` is renamed in its help text to "reproduce the original v2 runs"; it uses the free-text Critic,
  which the current paper does not describe.

## v3.5 (13 Nov 2026): Python and JavaScript checker fixes

Found by the first end-to-end run on Python and JavaScript projects (web app: ZIP upload, GitHub link, pasted code).
Java analysis, the benchmark harness and every paper number are unchanged; only `polyglot.py`, the two
polyglot catalogues and web labels changed.

| # | Problem in v3.4 | Fix |
|---|---|---|
| 1 | JS: every `res.sendFile(...)` / `res.download(...)` in an Express route was reported, even with a constant path, because the route's `res` parameter counted as the tainted path. A correct fix could never pass the graph gate. | Catalogues can say which arguments carry the path (`args`). For JS path sinks only the path argument counts, never the receiver. |
| 2 | JS: `fs.writeFile(path, data)` was reported when only `data` came from the user, so a sanitised upload path still failed the gate. Same for Python `Path(...).write_text(data)`. | Same `args` mechanism: content and options arguments are not paths (`rename`/`copyFile` check both paths; `write_text`/`write_bytes` check the receiver). |
| 3 | Python: the Flask/Werkzeug upload bug `request.files[...].save(os.path.join(dir, f.filename))` was missed. | `save` is a path sink, checked on its first positional argument only (so Django `.save()` / `.save(commit=False)` / `save(*args)` are not findings). |
| 4 | JS: the bare `open` sink matched any `.open()` method (`window.open`, `xhr.open`, `modal.open`), which gave false positives in bundled UI libraries. | Catalogues can restrict a sink name to an fs-like receiver (`receivers`): `open`, `rename`, `rm`, `mkdir` need `fs`, `fs.promises`, `fs-extra`, `require('fs')` or a destructured call; `download` needs `res`. `/vendor/` and `/bower_components/` folders are skipped like `node_modules`. |

Web: the classic UI's scan summary says "Source files" (was "Java files") and the paste box asks for Java, Python
or JavaScript code. Version string: v3.5.0 · 13 Nov 2026.

**v3.5.1:** the prebuilt React workspace (`frontend/dist/`) is back in the package. v3.4 and v3.5 shipped without it, so `python -m graphpatch_v2.server` fell back to the older one-page UI. The React source is unchanged since v3.3. Version string: v3.5.1.

Tests: 10 new tests in `tests/test_polyglot.py` (7 of them fail on v3.4); `python -m pytest graphpatch_v2/tests`:
147 passed, 1 skipped. End to end, the Express sample's repair now closes (4 paths -> 0); in v3.4 it was rejected
three times with 2 paths left.
