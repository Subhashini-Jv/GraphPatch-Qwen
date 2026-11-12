# Sample results (not paper results)

- `calibration.csv`: the taint checker on the vulnerable vs. the developers' fixed code for all CWE-Bench-Java CVEs.
- `sanity_noop_oracle.csv`: harness checks on 6 CVEs. `noop` = no change (must never verify), `oracle` = the developers' fix.
- `scripted_loop_spark/`: one run of `--mode full` on CVE-2018-9159 where the model was replaced by **scripted replies** to test the loop. Patch 1 is deliberately useless and is rejected by the path gate; patch 2 adds a validation guard. These are not LLM outputs and must not be reported as results.
