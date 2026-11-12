# Filling the paper with Qwen results

> **v3 (enhanced version).** Besides the Qwen runs, the scripts now also run the rule baseline
> again (no model; guards are recognized more strictly in v3) and the new `seeded` mode
> (GraphPatch + Rule). Add `-CodeQL` (PowerShell) or `GP_CODEQL=1` (Linux/macOS) to also judge
> every patch with CodeQL as an independent oracle; this needs the CodeQL bundle (see
> `graphpatch_v2/README.md`) and adds a few minutes per CVE. Results recorded by an older
> version are run again automatically, so old and new numbers never mix. See
> `graphpatch_v2/CHANGES_v3.md` for what changed.

**Quick way:** unzip, open PowerShell in this folder and run `.\run_qwen.ps1`
(Linux/macOS: `./run_qwen.sh`). It installs the Qwen model, runs all modes, and writes
`paper\results.tex`. Add `-NoAblation` to skip the two ablation modes. If your earlier runs
used `--tests related`, run `.\run_qwen.ps1 -Tests related`. You need Python 3.10+, git,
Ollama, and Docker or local JDK 8/17 + Maven (see `graphpatch_v2/README.md`).
The steps below are what the script does.

The paper (`graphpatch.tex`) reads every model result from `results.tex`. Until that file
exists, those cells print as a bold **?**. Everything else in the paper is already measured
and needs no model: the calibration (Table I), the rule baseline B0, the harness checks, and
the context sizes.

## 1. Prepare the model (once)

Ollama cuts prompts to 2,048 tokens by default, so make a copy with a larger context:

```powershell
ollama pull qwen2.5-coder:7b
"FROM qwen2.5-coder:7b`nPARAMETER num_ctx 24576" | Set-Content -Encoding ascii Modelfile.qwen
ollama create qwen2.5-coder-24k -f Modelfile.qwen
```

## 2. Run the 9 paper CVEs

Run from the folder that contains `graphpatch_v2/`. `--skip-done` lets you stop and continue later.

```powershell
$env:GP_LLM_TIMEOUT = "1800"   # a local model on a laptop CPU needs minutes per answer
$env:GP_LLM_MAX_TOKENS = "4096"
$cves = "CVE-2022-25842 CVE-2018-1002201 CVE-2018-1002200 CVE-2018-1002202 CVE-2018-17297 CVE-2020-35460 CVE-2018-12036 CVE-2022-31194 CVE-2022-26049".Split(" ")

# Needed for Tables III and IV (RQ1, RQ2, RQ4)
foreach ($m in "single", "nograph", "full") {
  python -m graphpatch_v2.run_eval run --mode $m --provider ollama --model qwen2.5-coder-24k --skip-done --cves $cves
}

# Needed for Table V (RQ3, ablation)
foreach ($m in "filectx", "nogate") {
  python -m graphpatch_v2.run_eval run --mode $m --provider ollama --model qwen2.5-coder-24k --skip-done --cves $cves
}
```

Use the same test setting you used for the earlier runs. If you used `--tests related` then, add
it here too.

## 3. Turn the results into the paper's numbers

```powershell
python fill_results.py gp_runs\results\runs.jsonl --model qwen2.5-coder-24k > paper\results.tex
```

The script warns about any mode that is missing CVEs. Put `results.tex` next to
`graphpatch.tex` and rebuild with `pdflatex graphpatch.tex` (run it twice). You can also send
`runs.jsonl` back and the PDF will be rebuilt for you.

## 4. Before submitting

- Search the PDF for a bold "?". There should be none left.
- Read Sections V-A to V-D once with the real numbers. The sentences are written for any
  outcome, but you may want to add a sentence about a notable CVE.
- If you skip the ablation runs (`filectx`, `nogate`), delete Table V and Section V-C (RQ3)
  and the RQ3 bullet.
