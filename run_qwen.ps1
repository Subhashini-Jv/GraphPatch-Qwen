# Runs the GraphPatch paper experiments with Qwen2.5-Coder-7B on Ollama, then writes paper\results.tex.
# Usage (PowerShell, inside this folder):   .\run_qwen.ps1            all 6 modes
#                                           .\run_qwen.ps1 -NoAblation   only single, nograph, full, seeded
#                                           .\run_qwen.ps1 -CodeQL      also judge with CodeQL (needs the CodeQL bundle)
#                                           .\run_qwen.ps1 -PaperMode   reproduce the paper exactly (enhancements off)
# Safe to stop and start again: finished CVEs are skipped.
param([switch]$NoAblation, [switch]$CodeQL, [switch]$PaperMode, [string]$Tests = "module")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$model = "qwen2.5-coder-24k"
$cves = "CVE-2022-25842 CVE-2018-1002201 CVE-2018-1002200 CVE-2018-1002202 CVE-2018-17297 CVE-2020-35460 CVE-2018-12036 CVE-2022-31194 CVE-2022-26049".Split(" ")

if (-not (Get-Command ollama -ErrorAction SilentlyContinue)) { throw "Ollama is not installed: get it from https://ollama.com/download" }
if (-not ((ollama list) -match [regex]::Escape($model))) {
    Write-Host "Creating $model (qwen2.5-coder:7b with a 24,576-token context)..."
    ollama pull qwen2.5-coder:7b
    "FROM qwen2.5-coder:7b`nPARAMETER num_ctx 24576" | Set-Content -Encoding ascii Modelfile.qwen
    ollama create $model -f Modelfile.qwen
}

python -m pip install -q -r graphpatch_v2\requirements.txt

$env:GP_LLM_TIMEOUT = "1800"      # a local model on a laptop CPU needs minutes per answer
$env:GP_LLM_MAX_TOKENS = "4096"   # patches are short; leaves room for the prompt in the context

$extra = @()
if ($CodeQL) { $extra += "--codeql-oracle" }
if ($PaperMode) { $extra += "--paper-mode" }      # reproduce the paper exactly (all enhancements off)

# B0 needs no model; it is re-run because v3 recognizes guards more strictly
Write-Host "`n=== mode rule (no model) ==="
python -m graphpatch_v2.run_eval run --mode rule --tests $Tests --skip-done @extra --cves $cves

$modes = @("single", "nograph", "full", "seeded")
if (-not $NoAblation) { $modes += @("filectx", "nogate") }
foreach ($m in $modes) {
    Write-Host "`n=== mode $m ==="
    python -m graphpatch_v2.run_eval run --mode $m --provider ollama --model $model --tests $Tests --skip-done @extra --cves $cves
}

python -m graphpatch_v2.run_eval summarize
$pm = @(); if ($PaperMode) { $pm += "--paper-mode" }
python fill_results.py gp_runs\results\runs.jsonl --model $model @pm | Set-Content -Encoding utf8 paper\results.tex
Write-Host "`nWrote paper\results.tex. Send gp_runs\results\runs.jsonl back, or build the PDF in paper\ with: pdflatex graphpatch.tex (twice)."
