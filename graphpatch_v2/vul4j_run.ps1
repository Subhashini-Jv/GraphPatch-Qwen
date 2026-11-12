# v2.19: run GraphPatch on Vul4J (79 real Java vulnerabilities with developer PoV tests) inside the Vul4J
# Docker image, which has the right JDKs, Maven/Gradle caches and the `vul4j` command.
# One-time:  docker pull tuhhsoftsec/vul4j      (about 13 GB download; needs about 35 GB free disk)
# Before running, in the same window:
#   cd E:\GraphPatch\GraphPatch ; docker desktop start
#   (LLM modes only) $env:GEMINI_API_KEY = "..."   <- set it here, never paste it in chat
# Free checks first (no model, no key):
#   .\graphpatch_v2\vul4j_run.ps1 -Mode oracle -Pilot     # the harness must verify the developers' fixes
#   .\graphpatch_v2\vul4j_run.ps1 -Mode noop -Pilot       # an empty patch must never verify
#   .\graphpatch_v2\vul4j_run.ps1 -Mode oracle            # all 79: which entries the harness can judge
#   .\graphpatch_v2\vul4j_run.ps1 -Mode rule              # the no-model baseline (B0)
# LLM modes (cost money with Gemini; ask Claude before starting):
#   .\graphpatch_v2\vul4j_run.ps1 -Mode full -Provider gemini -Model gemini-3.8-flash
# If it stops, run it again: finished CVEs are skipped. Results: gp_runs\results_vul4j
param(
    [Parameter(Mandatory = $true)][string]$Mode,
    [string]$Provider = "",
    [string]$Model = "",
    [string]$Cves = "",
    [switch]$Pilot
)
$here = (Get-Location).Path
if (-not (Test-Path "$here\graphpatch_v2\vul4j_bench.py")) { Write-Host "Run this from E:\GraphPatch\GraphPatch"; exit 1 }
New-Item -ItemType Directory -Force "$here\gp_runs\results_vul4j" | Out-Null
if ($Pilot) { $Cves = "VUL4J-10 VUL4J-41 VUL4J-1" }
$args_ = @("--benchmark", "vul4j", "run", "--mode", $Mode, "--skip-done")
if ($Cves) { $args_ += @("--cves") + ($Cves -split "\s+") }
if ($Provider) { $args_ += @("--provider", $Provider) }
if ($Model) { $args_ += @("--model", $Model) }
$llmTimeout = "600"
$maxTokens = "16384"
# Ollama cuts every prompt to the model's context (2048 tokens by default) and says nothing; our prompts are up to
# about 10k tokens. Make a copy of the model with a bigger context once, and use that name with -Model:
#   "FROM qwen2.5-coder:7b`nPARAMETER num_ctx 24576" | Set-Content -Encoding ascii Modelfile.qwen
#   ollama create qwen2.5-coder-24k -f Modelfile.qwen
if ($Provider -eq "ollama") {
    $maxTokens = "4096"     # patches are short; leaves room in the context for the prompt
    $args_ += @("--base-url", "http://host.docker.internal:11434/v1")
    $llmTimeout = "1800"    # a local model on a laptop CPU needs minutes per answer
}
$py = "/gp/gp_runs/vul4j/env/bin/python"
$setup = "test -x $py || (python3 -m venv /gp/gp_runs/vul4j/env && /gp/gp_runs/vul4j/env/bin/pip -q install javalang requests)"
$cmd = "$setup && cd /gp && $py -m graphpatch_v2.run_eval " + ($args_ -join " ")
# The checkouts live in a Docker volume (fast Linux disk, kept between runs); results come back to gp_runs\results_vul4j.
# -e GEMINI_API_KEY passes the key from this window into the container without writing it anywhere.
docker run --rm -e GEMINI_API_KEY -e GP_VUL4J_CMD=vul4j -e GP_LLM_TIMEOUT=$llmTimeout -e GP_LLM_MAX_TOKENS=$maxTokens `
    -v "${here}\graphpatch_v2:/gp/graphpatch_v2:ro" `
    -v gp_vul4j:/gp/gp_runs/vul4j `
    -v "${here}\gp_runs\results_vul4j:/gp/gp_runs/results_vul4j" `
    tuhhsoftsec/vul4j bash -c $cmd
if ($LASTEXITCODE -ne 0) { Write-Host "Stopped. Fix the problem shown above, then run this script again."; exit 1 }
