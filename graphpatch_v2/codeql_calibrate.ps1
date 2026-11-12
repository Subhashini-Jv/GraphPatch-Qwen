# v2.19: CodeQL as a second taint checker. Counts how many CWE-Bench-Java CVEs become judgeable.
# No language model, no API key, no Docker, no cost. It does not change any paper result.
# One-time setup: download codeql-bundle-win64.tar.gz from https://github.com/github/codeql-action/releases
# (the BUNDLE, it includes the Java queries) and unpack it:   tar -xzf codeql-bundle-win64.tar.gz -C E:\   (E: has more free space)
# Before running, in the same window:
#   cd E:\GraphPatch\GraphPatch ; venv\Scripts\Activate.ps1 ; $env:CODEQL = "E:\codeql\codeql.exe"
# Pilot (3 CVEs, shows how long one takes):   .\graphpatch_v2\codeql_calibrate.ps1 -Pilot
# Everything (can run overnight):              .\graphpatch_v2\codeql_calibrate.ps1
# If it stops, run it again: finished CVEs are skipped.
param([switch]$Pilot)
python -m graphpatch_v2.codeql check
if ($LASTEXITCODE -ne 0) { Write-Host "CodeQL is not set up yet. See the lines at the top of this script."; exit 1 }
if ($Pilot) {
    python -m graphpatch_v2.codeql --dataset cwe-bench-java-master calibrate --skip-done `
        --cves CVE-2022-25842 CVE-2018-1002200 CVE-2020-35460
} else {
    python -m graphpatch_v2.codeql --dataset cwe-bench-java-master calibrate --skip-done
}
Write-Host "`nUpload gp_runs\results\calibration_codeql.csv to the code thread."
