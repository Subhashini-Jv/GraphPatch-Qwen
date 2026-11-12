# v2.19.9: CodeQL as a second taint checker on Vul4J. Counts how many Vul4J CVEs CodeQL makes graph-judgeable.
# Runs on the 24 judgeable Vul4J CVEs whose CWE CodeQL has taint queries for (path traversal, XSS, XXE,
# deserialization, injection, SSRF). No language model, no API key, no Docker, no cost. Changes no paper result.
# Before running, in the same window:
#   cd E:\GraphPatch\GraphPatch ; venv\Scripts\Activate.ps1 ; $env:CODEQL = "E:\codeql\codeql.exe"
# Pilot (3 CVEs):            .\graphpatch_v2\codeql_vul4j.ps1 -Pilot
# Everything (some hours):   .\graphpatch_v2\codeql_vul4j.ps1
# If it stops, run it again: finished CVEs are skipped.
param([switch]$Pilot)
python -m graphpatch_v2.codeql check
if ($LASTEXITCODE -ne 0) { Write-Host "CodeQL is not set up yet. See codeql_calibrate.ps1."; exit 1 }
if ($Pilot) {
    python -m graphpatch_v2.codeql --benchmark vul4j calibrate --skip-done --cve-timeout 5400 --cves VUL4J-41 VUL4J-47 VUL4J-78
} else {
    python -m graphpatch_v2.codeql --benchmark vul4j calibrate --skip-done --cve-timeout 5400
}
Write-Host "`nUpload gp_runs\results\calibration_codeql_vul4j.jsonl to the code thread."
