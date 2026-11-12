# Run once a day on the free Gemini tier (5 requests/minute, 20/day).
# It continues where the last run stopped, and stops by itself when the daily quota is used up.
# Before running, in the same window:
#   cd E:\GraphPatch\GraphPatch ; venv\Scripts\Activate.ps1 ; docker desktop start ; $env:GEMINI_API_KEY="..."
# Then:  .\graphpatch_v2\daily_run.ps1
# Every paper number must come from ONE model; change it only before the first real run.
$model = "gemini-3.8-flash"
foreach ($mode in @("full", "single", "nograph")) {
    python -m graphpatch_v2.run_eval --dataset cwe-bench-java-master run --mode $mode `
        --provider gemini --model $model --cves-file graphpatch_v2\paper_cves.txt `
        --rpm 5 --skip-done --docker always
}
python -m graphpatch_v2.run_eval --dataset cwe-bench-java-master summarize
