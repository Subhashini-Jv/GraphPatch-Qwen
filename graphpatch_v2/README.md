# GraphPatch v2: graph-verified repair of Java vulnerabilities

GraphPatch v2 is a rewrite of the GraphPatch pipeline around one idea: **the code-graph query that finds the vulnerable data flow is also the check that the fix worked.** The same query gives the LLM its context and decides whether to accept the patch.

1. The code graph finds a **taint path**: untrusted input (an archive entry name, an HTTP parameter, a parameter of the vulnerable method) flowing into a dangerous call (`new FileOutputStream`, `Runtime.exec`, `out.print`, `parseExpression`, ...).
2. The Planner and Coder agents get **that path plus the real source code** of the methods on it, not file names.
3. A patch is only accepted when the project **builds**, its **tests show no new failures**, and the **path is gone**. If the path is still there, the Critic agent gets the remaining path ("`destFile` still reaches `FileUtils.copy` at line 1239") and the loop tries again.
4. The final verdict uses two **held-out** checks the agents never see. First, the patch must remove every taint path that the developers' own fix removed. Second, where they exist, **proof-of-vulnerability (PoV) tests** from the fix commit (tests that fail on the vulnerable code and pass on the real fix) must pass.

It lives next to your old `src/` and does not change it.

## New in v3

Five enhancements taken from the paper's Future Work and Threats to Validity: edit-distance SEARCH
placement, a Critic that answers in checked JSON, stricter guard recognition, the `seeded` mode
(GraphPatch + Rule) and CodeQL as an independent held-out oracle (`--codeql-oracle`). Details, file
locations and what is not re-measured: [CHANGES_v3.md](CHANGES_v3.md).

```bash
python -m graphpatch_v2.run_eval run --mode seeded --provider ollama --model qwen2.5-coder-24k --cves CVE-2018-17297
python -m graphpatch_v2.run_eval run --mode full --provider ollama --model qwen2.5-coder-24k --codeql-oracle --cves CVE-2018-1002201
python -m graphpatch_v2.codeql judgeable --only-new     # CVEs only CodeQL can judge, for --cves-file
```

## What changed compared with the old pipeline

| Old pipeline | v2 |
|---|---|
| Every CVE ran against the same `./data/repos` folder | Each CVE is checked out at its own vulnerable commit (git worktree), with the dataset's build patch applied |
| LLM saw only `File: ... Class: ... Method: ...` | LLM sees the taint path and the numbered source of every method on it |
| Patch = whole file written from memory, or a hardcoded `SecurityFix.java` mock | Patch = SEARCH/REPLACE edits on the real files. No mock: if the model fails, the CVE is recorded as an error |
| `mvn ... \| head -50`, errors turned into success, tests never run | Real exit codes. `test-compile`, then the module's tests, compared with a baseline run on the unpatched code |
| One retry | Loop up to `--max-iters` (default 3), every iteration logged |
| Success = validator said so | `verified` / `plausible` / `rejected`, plus separate graph and PoV results |
| Regex "CPG" over the first 100 files | Java AST (javalang) with intra-method data flow, field flow and call edges between analysed methods |

## Install

Python 3.10 or newer, git, and either Docker or local JDKs plus Maven.

```bash
pip install -r graphpatch_v2/requirements.txt
```

Builds use Docker (`maven:3.9-eclipse-temurin-8/17`) when it is running. Without Docker, set the JDKs the benchmark needs:

```bash
# Linux / WSL
export GP_JDK8_HOME=/usr/lib/jvm/java-8-openjdk-amd64
export GP_JDK17_HOME=/usr/lib/jvm/java-17-openjdk-amd64
```
```powershell
# Windows PowerShell
$env:GP_JDK8_HOME="C:\Program Files\Eclipse Adoptium\jdk-8.0.x"
$env:GP_JDK17_HOME="C:\Program Files\Eclipse Adoptium\jdk-17.0.x"
```

API keys come only from environment variables (never from code):

```bash
export GEMINI_API_KEY=...      # or GROQ_API_KEY, OPENROUTER_API_KEY, DEEPSEEK_API_KEY, OPENAI_API_KEY
```

## Run

All commands run from the folder that contains `graphpatch_v2/`. Results go to `gp_runs/` (change with `--root`). The CWE-Bench-Java dataset is cloned there on first use.

```bash
# 1. Calibrate the taint checker against the real fixes (no LLM, no builds, minutes)
python -m graphpatch_v2.run_eval calibrate

# 2. Sanity checks on a few CVEs (no LLM): the real fix should pass, "no change" must not
python -m graphpatch_v2.run_eval run --mode oracle --cves CVE-2018-1002201 CVE-2022-25842 CVE-2018-9159
python -m graphpatch_v2.run_eval run --mode noop   --cves CVE-2018-1002201 CVE-2022-25842 CVE-2018-9159

# 3. Repair with the full system
python -m graphpatch_v2.run_eval run --mode full --provider gemini --model <model-name> --cves CVE-2018-1002201

# 4. Baselines and ablations for the paper, same model, same CVEs
for m in single agent nograph filectx nogate; do
  python -m graphpatch_v2.run_eval run --mode $m --provider gemini --model <model-name> --cves ...
done

# 5. Tables
python -m graphpatch_v2.run_eval summarize
```

**On the free Gemini tier** (5 requests per minute, 20 per day) use `--rpm 5 --skip-done`: calls are spaced out, the run stops cleanly when the daily quota is used up, and the next run skips CVEs that are already finished. `daily_run.ps1` does this for the core paper set in `paper_cves.txt` (the 15 CVEs where the checker can judge a patch) with GraphPatch, B1 and B3.

If a model's replies get cut off, raise `GP_LLM_MAX_TOKENS` (default 16384; cut-off replies are retried with a larger limit automatically).

Useful options: `--cwe CWE-022`, `--limit 10`, `--tests related` (only tests named after the vulnerable classes, falls back to the module's tests when none match; much faster on big projects), `--tests skip` (fast, but no patch can be verified), `--max-iters 3`, `--docker never`, `--no-pov`.

### Modes

| Mode | Context | Loop gates | Agents | Paper name |
|---|---|---|---|---|
| `full` | taint paths + methods on them | build + tests + paths | Planner, Coder, Critic | GraphPatch |
| `filectx` | whole vulnerable files | build + tests + paths | Planner, Coder, Critic | ablation: no path-sliced context |
| `nogate` | taint paths + methods on them | build + tests | Planner, Coder, Critic | ablation: no path gate |
| `nograph` | whole vulnerable files | build + tests | Planner, Coder, Critic | B3: multi-agent, tests only |
| `agent` | whole vulnerable files | build + tests | one Coder with raw feedback | B2: single agent |
| `single` | whole vulnerable files | none (one call) | one Coder | B1: single prompt |
| `rule` | taint paths | none (one pass) | no model: a fixed rule (`rules.py`) | B0: rule-based fix |
| `oracle` | the developers' fix | | | harness check: should verify |
| `noop` | no change | | | harness check: must never verify |

Every mode goes through the same validator, so the numbers are comparable.

`rule` needs no model and no key (`rule_run.ps1` runs it on the paper set). For path traversal it adds the
standard containment check after the tainted `File` is built: normalise the path and throw unless it stays inside
the base directory (or, when no base directory is known, reject `..`). Other CWEs have no rule and end as `no_edits`.
The rule reads the same taint paths as the gate, so it is a strong test of the gate, not of real-world repair.

## Developer tools (no model, no key)

| Command | What it does |
|---|---|
| `python -m graphpatch_v2.sarif <project> --out graphpatch.sarif` | findings as SARIF 2.1.0 for GitHub code scanning (below) |
| `python -m graphpatch_v2.deps <project>` | declared Maven/Gradle libraries with known vulnerabilities, from the free OSV.dev database (needs internet; declared dependencies only, not transitive ones) |
| `python -m graphpatch_v2.precommit --install` | git pre-commit hook: blocks a commit when a staged Java file has a taint path (`github/pre-commit-hooks.yaml` for the pre-commit framework) |
| `python -m graphpatch_v2.attacktest <project> --out DIR` | writes a JUnit attack test per path-traversal finding: it tries to write outside the target folder and fails while the bug is there |

The web app shows a 0-100 risk score per finding (kind of bug, real untrusted input or only a parameter, what the
dangerous call does, path length; a triage aid, not a probability), a library check, a SARIF download, a
no-key rule fix, a Compare view per CVE, an offline Replay of saved benchmark runs, and tokens and time per verified
fix on the Results page (set `GP_PRICE_IN` / `GP_PRICE_OUT`, price per million tokens, to also see cost).

## Vul4J, a second benchmark (v2.19)

`vul4j_bench.py` runs every mode on Vul4J's 79 vulnerabilities that have developer proof-of-vulnerability
(PoV) tests (dataset copy in `benchmarks/`, CC-BY-4.0, Bui et al., MSR 2022). Everything runs inside the
`tuhhsoftsec/vul4j` Docker image through `vul4j_run.ps1`; results go to `gp_runs/results_vul4j`.

- The human patch and the PoV test classes are moved out of the checkout and its git history is replaced
  by one baseline commit, so no model sees them. They come back only for the final verdict.
- Build and tests use the dataset's own commands (`vul4j compile`, `vul4j test`), compared with a baseline.
- Final verdict: the PoV tests must pass, plus the graph check where the taint checker has rules (path
  traversal, command injection, XSS, code injection; other CWEs get no graph feedback, so `full` there
  is close to `nograph`). Before any patch is judged, the harness checks once per CVE that the PoV tests
  fail on the vulnerable code and pass on the human fix.
- The summary also prints "PoV pass (Vul4J protocol)": compiles and PoV tests pass, other tests not
  checked, which is how `vul4j evaluate` and published Vul4J results count a fix.
- v2.19.4: a results file left with half a line by a power cut is read safely; that CVE just runs again.
- v2.19.3: PoV test files are also found when the dataset spells the package in different case (VUL4J-44).
- v2.19.2: deleting a checkout's `.git` waits for git's background clean-up and retries (VUL4J-37).
- PoV tests may be Java, Groovy, Kotlin or Scala files (v2.19.1: VUL4J-22 has a Groovy PoV). After
  updating, rerun the same mode with `vul4j_run.ps1`; finished CVEs are skipped and error rows run again.

```
docker pull tuhhsoftsec/vul4j                          # once, about 13 GB
.\graphpatch_v2\vul4j_run.ps1 -Mode oracle -Pilot       # free: must verify the developers' fixes
.\graphpatch_v2\vul4j_run.ps1 -Mode rule                # free: the B0 baseline on all 79
```

## CodeQL as a second checker (v2.19, no model, no key)

`codeql.py` runs GitHub's CodeQL (Java security-extended suite, `--build-mode=none`, so no Maven/Gradle or
Docker) on the vulnerable commit and on the real fix, keeping only taint paths that touch the files the
fix changed. A CVE is judgeable when CodeQL finds a path on the vulnerable code and the real fix removes
one, the same rule `calibrate` uses for the javalang checker. The report shows, per CWE, how many CVEs are
judgeable by javalang, by CodeQL, and by either.

```
python -m graphpatch_v2.codeql check                                   # CodeQL bundle installed?
.\graphpatch_v2\codeql_calibrate.ps1 -Pilot                             # 3 CVEs, to time it
.\graphpatch_v2\codeql_calibrate.ps1                                    # all 120, resumable
python -m graphpatch_v2.codeql report                                  # table again
```

Each CodeQL step may take at most `--timeout` seconds (default 1800); a slower CVE (very large projects such as
Apache CXF) is recorded as `timeout` and not retried by `--skip-done`.
v2.19.8: a CVE's CWE also accepts CodeQL queries tagged with a related CWE (CWE-094 takes OGNL/SpEL CWE-917 and template CWE-1336;
CWE-078 takes CWE-077/088), and the CSV and table always cover every CVE run so far.
`--exclude CVE-...` skips CVEs by hand (recorded as `skipped`). Each step prints a progress line (cloning, checking out,
CodeQL), so a slow step is visible.

Output: `gp_runs/results/calibration_codeql.csv` (`reduced_by_fix` = judgeable; `fewer_after_fix` is the
stricter count where the fix leaves fewer alerts). This step only measures; the repair loop still uses
the javalang checker.

v2.19.9, Vul4J: `.\graphpatch_v2\codeql_vul4j.ps1 [-Pilot]` (or `python -m graphpatch_v2.codeql --benchmark vul4j calibrate`)
runs the same check on the 24 judgeable Vul4J CVEs whose CWE CodeQL has taint queries for (CWE-22, 74, 77, 78, 79,
502, 611, 918). Vul4J lists only the fix commit, so the vulnerable code is the fix commit's first parent; the fix's
files come from the oracle run's diffs (`benchmarks/vul4j_fix_files.json`). It clones from GitHub on the host, so
Docker is not needed. Output: `gp_runs/results/calibration_codeql_vul4j.csv`.

v2.19.10: each CVE also has a total time limit (`--cve-timeout`, default 2 x `--timeout` = 1 hour) covering clone,
checkouts and CodeQL. After a timeout or Ctrl+C, leftover java/codeql/git processes working in gp_runs are killed too
(taskkill alone missed Java started by codeql.exe, which kept Apache CXF running for hours). A slow step prints a
"still running" line every 5 minutes.

v2.19.11: the Vul4J check now uses the same code `vul4j checkout` uses: the vulnerable code is the head of the
`VUL4J-n` branch in github.com/tuhh-softsec/vul4j, and the fixed code is that tree with the human patch's files from
the fix commit. (Some old upstream commits are gone from GitHub, e.g. Apache Sling.) Only if a branch is missing does
it fall back to the fix commit's parent in the project's repository. Rows show which (`source`). Vul4J rows from
v2.19.9/10 are redone automatically; their timeouts are kept. `codeql_vul4j.ps1` allows 90 minutes per CVE.
v2.19.12: the Vul4J table always counts all 24 CVEs and our checker's 4, also after a run with `--cves` (it showed only the CVEs just run, so 'new' was wrong; the saved results were not affected).
v2.19.13: `vul4j_run.ps1 -Provider ollama` allows 30 minutes per model answer (GP_LLM_TIMEOUT), because a local model on a laptop CPU is slow.
v2.19.14: Ollama silently cuts prompts to the model's context (2048 tokens by default), so in the first pilot the model saw only the end of the code and wrote edits for lines it never saw. A run now stops with a clear message when that happens. Make a copy of the model with `num_ctx 24576` (see `vul4j_run.ps1`); Ollama replies are capped at 4096 tokens.
v2.19.15: when a local model gives no answer within the timeout, the run stops with a message instead of retrying up to 8 times (that kept a pilot busy for a day).

v2.19.16: new web app look (chosen by Lucifer): dark sidebar menu on the left, light pages, teal accent, Inter font; roomier tables; the results chart axis now ends at the number of judged CVEs. Only the web files changed (web/style.css, web/index.html, one line in web/app.js); the pipeline and results are unchanged.

v2.19.17: new homepage (chosen by Lucifer): the repair pipeline drawn as its real stages (program graph, Planner, Coder, Critic, Verifier) with the retry loop, then verified fixes per approach and the Zip Slip example. Web files only.

v2.19.18: easier to use: Scan & Fix shows the 4 steps (choose, see paths, fix, check) and groups the buttons into Fix and Export; "Repair with agents" without a key now explains how to add one instead of being greyed out; Benchmark has All / Judged / Excluded filters; Results explains what verified, plausible and rejected mean. Web files only.

v2.19.19: "Repair with agents" can use a free Groq key when Gemini is blocked: set $env:GP_LLM_PROVIDER = "groq" and $env:GROQ_API_KEY before starting the app (default model llama-3.3-70b-versatile; change with $env:GP_LLM_MODEL). Gemini stays the default. Groq was not reachable from the build machine, so this was tested with a fake key only. Paper and benchmark results all come from gemini-3.8-flash.

v3.5: Python and JavaScript checker fixes from the first end-to-end test (Express `res.sendFile` and `fs.writeFile` false positives, Flask `f.save()` uploads now found, `.open()` only on fs objects, vendor folders skipped). Java and the paper's numbers are unchanged. Details: [CHANGES_v3.md](CHANGES_v3.md#v35-13-nov-2026-python-and-javascript-checker-fixes).

v2.19.20: when the agents fail, the page explains why in plain words (blocked Google account, wrong key, quota) and points to Rule fix and Replay; the key help no longer mentions Groq (the Groq option still works if GP_LLM_PROVIDER=groq is set).

## GitHub code scanning (SARIF)

```
python -m graphpatch_v2.sarif <java project folder> --out graphpatch.sarif   # no model, no key
```

writes every taint path as a SARIF 2.1.0 result at its sink, with the whole path in the message.
`github/graphpatch.yml` is the workflow for this repository (unit tests + scan + upload); copy it to
`.github/workflows/`. `github/scan-any-java-repo.yml` adds GraphPatch to any other Java repository. Results then
appear under Security > Code scanning and on pull requests (free on public repositories; private ones need
GitHub Code Security, and the SARIF file is kept as a build artifact either way).

## Outputs

- `gp_runs/results/runs.csv`: one row per CVE and mode. Key columns are `status` (verified / plausible / rejected / excluded / error), `graph_ok`, `pov_ok`, `paths_before`, `paths_after`, `tests_run`, `new_test_failures`, `iterations`, `llm_calls`, `prompt_tokens`, `completion_tokens`, `context_chars` and `file_context_chars` (for the context-reduction number), `deleted_targets` and `seconds`.
- `gp_runs/results/artifacts/<mode>/<slug>/`: `paths_before.txt`, `plan.md`, `patch_N.diff`, `verdict_N.json`, `verdict_final.json`, `final.diff`, and `transcript.json` (every prompt and reply).
- `gp_runs/results/calibration.csv`: per CVE, the paths found on the vulnerable code and on the real fix.

`excluded` means the unpatched project does not build in your environment. Those CVEs are left out of every percentage and listed separately, which you should also do in the paper.

## Checked so far (in a Linux container, local JDK 8/17, no Docker, no LLM key)

- **Unit tests:** 15 pass (`python -m pytest graphpatch_v2/tests`).
- **Checker calibration on the developers' fixes** (115 CVEs that have main-source fix locations):

  | CWE | CVEs | path found on vulnerable code | real fix removes all paths | real fix removes at least one |
  |---|---|---|---|---|
  | CWE-22 path traversal | 53 | 21 | 8 | 13 |
  | CWE-78 command injection | 13 | 1 | 1 | 1 |
  | CWE-79 XSS | 29 | 8 | 0 | 1 |
  | CWE-94 code injection | 20 | 3 | 0 | 0 |
  | all | 115 | 33 | 9 | 15 |

- **Harness checks on 6 path-traversal CVEs** (Spark CVE-2018-9159, one-java-agent CVE-2022-25842, zt-zip CVE-2018-1002201, plexus-archiver CVE-2018-1002200, zip4j CVE-2018-1002202, hutool CVE-2018-17297). All 6 build, and their tests run (zip4j has none). With no change, 0 of 6 are verified. With the developers' fix, 5 of 6 are verified. Spark cannot be judged: its real fix removes none of the paths the checker finds (it leaves the protected constructor unchecked), and it has no PoV test. zt-zip's PoV test fails on the vulnerable code and passes on the fix, as intended.
- **Repair loop:** run end to end on Spark with a scripted stand-in for the model (test only, not shipped). A first patch that only changed formatting built and passed 195 tests. The path gate rejected it and the Critic received the remaining paths. The second patch removed all paths.
- **Not run here:** a real LLM (no API key, and Groq is blocked in this container) and Docker builds.

## How this maps to the paper

| Research question | Where the number comes from |
|---|---|
| RQ1: how many CVEs each system really fixes | `verified` per mode in `summarize` (`single`=B1, `agent`=B2, `nograph`=B3, `full`=GraphPatch) |
| RQ2: how many patches pass build and tests but are still vulnerable | "tests pass but still vulnerable" column (`plausible` with `graph_ok` or `pov_ok` false) |
| RQ3: what path context and the path gate each add, and how much context they save | `full` vs `filectx` and `nogate`; `context_chars` vs `file_context_chars` |
| RQ4: cost | `prompt_tokens`, `completion_tokens`, `iterations`, `seconds` |
| Threats to validity: how good the checker is | `calibrate` table |

## Limitations (state these in the paper)

- **The path gate in the loop and the graph score in the final verdict differ on purpose.** In the loop, the agents are asked to remove every path the checker finds, since nothing else is known at repair time. The final verdict only requires removing the paths the developers' fix removed, because the calibration shows the real fix often leaves some checker findings in place.
- **The taint checker is approximate.** It is flow-insensitive within a method, tracks fields within one class, follows calls only between the vulnerable files and their same-package neighbours, and recognises sources, sinks, sanitizers and guards from per-CWE lists in `taint.py`. The `calibrate` command measures how often it finds a path on the vulnerable code and how often the real fix removes it. Report those numbers.
- **It works best on path traversal (CWE-22).** Many CWE-79 CVEs in this benchmark are bugs inside HTML sanitizer libraries (AntiSamy, xwiki), and many CWE-94 fixes change an evaluation context or a deny-list rather than cut a data flow. A source-to-sink check cannot judge those, so they rely on PoV tests, or end up `plausible`.
- **A guard is recognised by its shape** (an `if` that throws or returns, or `Assert.isTrue(...)`-style calls). A model could write a guard that looks right but checks nothing useful. The held-out PoV tests and a manual check of a sample of `verified` patches against the real fix are the protection against that; report the manual check.
- **Localisation is given.** Sources are the parameters of the methods the benchmark marks as vulnerable. Say so in the paper ("perfect fault localisation" setting, as in most repair papers).
- **PoV tests exist only for some CVEs.** They are used only when a fix-commit test fails on the vulnerable code and passes on the real fix.
- **Docker was not available where this was built.** The Docker path follows the official image documentation but was not run; the local-JDK path was.

## Files

| File | What it does |
|---|---|
| `run_eval.py` | command line: `calibrate`, `run`, `summarize` |
| `pipeline.py` | one CVE in one mode: checkout, baseline, agents loop, validation, artifacts |
| `taint.py` | code graph and taint paths (sources, sinks, sanitizers, guards per CWE) |
| `validator.py` | strict acceptance: compile, tests, taint check, held-out PoV tests |
| `build.py` | Maven/Gradle in Docker or with local JDKs; baseline test comparison |
| `agents.py` | Planner, Coder, Critic prompts and the two kinds of code context |
| `llm.py` | one OpenAI-compatible client for Gemini, Groq, OpenRouter, DeepSeek, OpenAI, Ollama |
| `workspace.py` | per-CVE git worktrees, resets, the real fix, PoV test overlay |
| `dataset.py` | CWE-Bench-Java loading |
| `calibrate.py` | checker vs. real fixes |
| `vul4j_bench.py` | Vul4J benchmark: workspace with hidden fix and PoV tests, `vul4j` build/test, PoV oracle (`vul4j_run.ps1`) |
| `codeql.py` | CodeQL as a second checker: calibration on vulnerable vs. fixed code (`codeql_calibrate.ps1`) |
| `javasrc.py` | Java parsing, method ranges, SEARCH/REPLACE edits |
| `rules.py` | the no-model `rule` baseline (containment check for path traversal) |
| `scanner.py` | whole-project scan (web app and SARIF) |
| `deps.py` | library check against OSV.dev |
| `precommit.py` | git pre-commit guard |
| `attacktest.py` | JUnit attack-test generator for path traversal |
| `sarif.py` | SARIF export for GitHub code scanning; `github/` holds the workflows and a small vulnerable demo |
| `tests/` | unit tests: `python -m pytest graphpatch_v2/tests` |

## Web app

```
pip install fastapi uvicorn python-multipart
$env:GEMINI_API_KEY = "..."        # only needed for repairs
python -m graphpatch_v2.server      # opens http://localhost:8000
```

- **Overview**: the approach and headline numbers.
- **Scan & Fix**: upload a zipped Java project, paste a public GitHub link (downloaded as a zip, no git needed),
  paste one Java class, or use the built-in Zip Slip example. See every taint path as a
  source → sink graph next to the highlighted code, and let the Planner/Coder/Critic agents repair it live.
  The patch is accepted when re-running the taint analysis finds the paths gone and the code still parses
  (uploaded projects are not compiled; benchmark CVEs are). The patched project can be downloaded, and
  "Report" opens a printable HTML report of the findings and the repair (print it to PDF from the browser).
- **Benchmark**: every paper CVE × approach from gp_runs/results, with the taint paths, every patch try,
  the final diff and the agent conversation; "Run again" re-runs one CVE in one mode.
- **Results**: outcome per approach, "tests pass but still vulnerable", tokens and time.

API docs at http://localhost:8000/api/docs. Don't start runs from the page while daily_run.ps1 is running.
