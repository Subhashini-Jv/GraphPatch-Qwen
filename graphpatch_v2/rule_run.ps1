# v2.17: the rule-based baseline (B0). No language model, no API key, no cost.
# It adds the standard "stay inside the target folder" check on every taint path (path traversal only)
# and is judged by exactly the same build, test, path and held-out checks as the other modes.
# Run it only after the v2.16 rerun has finished and gp_results.zip is uploaded.
# Before running, in the same window:
#   cd E:\GraphPatch\GraphPatch ; venv\Scripts\Activate.ps1 ; docker desktop start
# Then:  .\graphpatch_v2\rule_run.ps1
# If it stops, run it again: finished CVEs are skipped.
python -m graphpatch_v2.run_eval --dataset cwe-bench-java-master run --mode rule `
    --cves-file graphpatch_v2\paper_cves.txt --skip-done --docker always
if ($LASTEXITCODE -ne 0) { Write-Host "Stopped. Fix the problem shown above, then run this script again."; exit 1 }
python -m graphpatch_v2.run_eval --dataset cwe-bench-java-master summarize
