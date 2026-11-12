# v2.16: rerun only the runs whose result was not caused by the model:
# - the old edit parser dropped edit blocks (one FILE: line followed by several blocks);
# - CVE-2022-26049 in full and single: the Gradle wrapper download timed out (network), reported as "does not compile".
# No other run had a dropped block or a network failure, so v2.16 would not change them.
# Before running, in the same window:
#   cd E:\GraphPatch\GraphPatch ; venv\Scripts\Activate.ps1 ; docker desktop start ; $env:GEMINI_API_KEY="..."
# Then:  .\graphpatch_v2\redo_runs.ps1
# If it stops (no credit, no internet), fix that and run it again: finished reruns are skipped.
$model = "gemini-3.8-flash"
$redo = @{
    "full"    = @("CVE-2018-17297", "CVE-2018-12036", "CVE-2018-1002201", "CVE-2022-26049");
    "nograph" = @("CVE-2022-31194", "CVE-2018-1002201");
    "single"  = @("CVE-2018-12036", "CVE-2018-1002201", "CVE-2022-26049")
}
foreach ($mode in @("full", "single", "nograph")) {
    python -m graphpatch_v2.run_eval --dataset cwe-bench-java-master run --mode $mode `
        --provider gemini --model $model --cves $redo[$mode] --rpm 5 --skip-done --redo-old-parser --docker always
    if ($LASTEXITCODE -ne 0) { Write-Host "Stopped. Fix the problem shown above, then run this script again."; exit 1 }
}
python -m graphpatch_v2.run_eval --dataset cwe-bench-java-master summarize
