#!/usr/bin/env bash
# Linux/macOS version of run_qwen.ps1.  Usage: [GP_CODEQL=1] ./run_qwen.sh [--no-ablation]
set -euo pipefail
cd "$(dirname "$0")"
MODEL=qwen2.5-coder-24k
CVES="CVE-2022-25842 CVE-2018-1002201 CVE-2018-1002200 CVE-2018-1002202 CVE-2018-17297 CVE-2020-35460 CVE-2018-12036 CVE-2022-31194 CVE-2022-26049"
TESTS=${GP_TESTS:-module}

command -v ollama >/dev/null || { echo "Ollama is not installed: https://ollama.com/download"; exit 1; }
if ! ollama list | grep -q "$MODEL"; then
  ollama pull qwen2.5-coder:7b
  printf 'FROM qwen2.5-coder:7b\nPARAMETER num_ctx 24576\n' > Modelfile.qwen
  ollama create "$MODEL" -f Modelfile.qwen
fi
python3 -m pip install -q -r graphpatch_v2/requirements.txt

export GP_LLM_TIMEOUT=1800 GP_LLM_MAX_TOKENS=4096
# GP_CODEQL=1 adds CodeQL as an independent held-out oracle (needs the CodeQL bundle, see graphpatch_v2/README.md)
EXTRA=""
[ "${GP_CODEQL:-0}" = "1" ] && EXTRA="--codeql-oracle"
# GP_PAPER_MODE=1 reproduces the paper exactly (all enhancements off)
[ "${GP_PAPER_MODE:-0}" = "1" ] && EXTRA="$EXTRA --paper-mode"

# B0 needs no model; it is re-run because v3 recognizes guards more strictly
echo "=== mode rule (no model) ==="
python3 -m graphpatch_v2.run_eval run --mode rule --tests "$TESTS" --skip-done $EXTRA --cves $CVES
MODES="single nograph full seeded"
[ "${1:-}" = "--no-ablation" ] || MODES="$MODES filectx nogate"
for m in $MODES; do
  echo "=== mode $m ==="
  python3 -m graphpatch_v2.run_eval run --mode "$m" --provider ollama --model "$MODEL" --tests "$TESTS" --skip-done $EXTRA --cves $CVES
done
python3 -m graphpatch_v2.run_eval summarize
PM=""; [ "${GP_PAPER_MODE:-0}" = "1" ] && PM="--paper-mode"
python3 fill_results.py gp_runs/results/runs.jsonl --model "$MODEL" $PM > paper/results.tex
echo "Wrote paper/results.tex"
