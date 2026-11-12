"""Repair one CVE in one mode.

  mode      context        loop gates                agents                    paper name
  full      taint paths    build + tests + paths     Planner, Coder, Critic    GraphPatch
  filectx   whole files    build + tests + paths     Planner, Coder, Critic    ablation: no path-sliced context
  nogate    taint paths    build + tests             Planner, Coder, Critic    ablation: no path gate
  nograph   whole files    build + tests             Planner, Coder, Critic    B3 multi-agent, tests only
  agent     whole files    build + tests             one Coder, raw feedback   B2 single agent
  single    whole files    none (one call)           one Coder                 B1 single prompt
  rule      taint paths    none (one pass)           no model: fixed rule      B0 rule-based fix (rules.py)
  seeded    taint paths    build + tests + paths     rule patch first, then    GraphPatch+Rule: the B0 patch is
                                                     Planner, Coder, Critic    candidate 1; the model takes over
                                                                               only if it fails a gate
  oracle    the developers' fix                                              harness check: should verify
  noop      no change                                                        harness check: must never verify

Every mode is validated by the same strict validator, so the numbers compare.
"""

from __future__ import annotations

import json
import time
import traceback
from dataclasses import dataclass
from pathlib import Path

from . import agents
from .build import Builder
from .calibrate import spec_for
from .dataset import CVE, Dataset
from .javasrc import apply_edits, parse_edits
from .llm import LLM, LLMError, StopRun
from .rules import rule_patch
from .validator import Validator, Verdict, scan
from .workspace import Workspace

# mode -> (context, path gate in the loop, multi-agent)
LOOP_MODES = {
    "full": ("graph", True, True),
    "filectx": ("file", True, True),
    "nogate": ("graph", False, True),
    "nograph": ("file", False, True),
    "agent": ("file", False, False),
    "seeded": ("graph", True, True),
}
LLM_MODES = tuple(LOOP_MODES) + ("single",)
MODES = LLM_MODES + ("rule", "oracle", "noop")


@dataclass
class Config:
    root: Path
    out: Path
    max_iters: int = 3
    tests: str = "module"          # module | related | skip
    use_docker: str = "auto"       # auto | always | never
    build_timeout: int = 1800
    test_timeout: int = 2400
    pov: bool = True               # find and run held-out proof-of-vulnerability tests
    codeql: str | None = None      # path to the CodeQL CLI: adds CodeQL as a held-out oracle (codeql_oracle.py)
    codeql_timeout: int = 3600
    fuzzy_edits: bool = True       # edit-distance SEARCH placement (off in --paper-mode)
    strict_guards: bool = True     # stricter guard recognition (off in --paper-mode)
    structured_critic: bool = True # Critic answers in checked JSON (--free-critic for the paper's free-text Critic)
    llm: LLM | None = None


def run_cve(cve: CVE, ds: Dataset, mode: str, cfg: Config) -> dict:
    t0 = time.time()
    from . import taint
    taint.STRICT_GUARDS = cfg.strict_guards
    art = cfg.out / mode / cve.slug
    art.mkdir(parents=True, exist_ok=True)
    for old in art.iterdir():  # files from an earlier run of this CVE and mode would mix with this one
        if old.is_file():
            old.unlink()
    row = {"slug": cve.slug, "cve": cve.cve_id, "cwe": cve.cwe, "mode": mode,
           "model": getattr(cfg.llm, "model", "") if mode in LLM_MODES else "",
           "status": "error", "stage": "setup", "iterations": 0,
           "critic": "json" if cfg.structured_critic else "free",
           "paper_mode": not (cfg.structured_critic or cfg.fuzzy_edits or cfg.strict_guards)}
    transcript = []
    ws = None
    try:
        # a benchmark other than CWE-Bench-Java (vul4j_bench.py) brings its own workspace, build and PoV oracle
        ws = (ds.make_workspace(cve, cfg.root) if hasattr(ds, "make_workspace") else Workspace(cve, ds, cfg.root)).prepare()
        spec = spec_for(cve)
        before = scan(ws.path, spec)
        row["paths_before"] = len(before)
        (art / "paths_before.txt").write_text("\n\n".join(f.render() for f in before) or "(none found)", encoding="utf-8")
        if hasattr(ds, "make_builder"):
            builder = ds.make_builder(ws, cfg)
        else:
            builder = Builder(ws.path, jdk=cve.build.get("jdk_version", "17"), target_files=cve.target_files,
                              use_docker=cfg.use_docker, build_timeout=cfg.build_timeout,
                              test_timeout=cfg.test_timeout, tests=cfg.tests)
        row["docker"] = builder.docker

        # ---- baseline: the unpatched project must build, and we record which tests already fail
        if not builder.has_baseline():
            c = builder.compile()
            if not c.ok:
                stage = "baseline_build_timeout" if c.stage == "compile_timeout" else "baseline_build_failed"
                row.update(status="excluded", stage=stage, error=(c.errors[:3] or [c.log_tail[-400:]]))
                (art / "baseline_build.log").write_text(c.log_tail, encoding="utf-8")
                return _finish(row, t0, art, transcript)
            if cfg.tests != "skip":
                b = builder.test(baseline=True)
                row["baseline_tests_run"] = b.tests_run
                row["baseline_failures"] = len(b.failed_tests)
                if b.stage == "tests_timeout":
                    row.update(status="excluded", stage="baseline_tests_timeout")
                    return _finish(row, t0, art, transcript)
                if b.tests_run == 0:
                    # the project has no runnable tests: build + security oracles only, flagged in the results
                    (builder.state_dir / "test_scope").write_text("skip", encoding="utf-8")
                    builder.tests = "skip"
        if builder.tests == "skip" and cfg.tests != "skip":
            row["no_tests"] = True

        make_validator = getattr(ds, "make_validator", Validator)
        validator = make_validator(ws, spec, builder, before, require_tests=builder.tests != "skip")
        validator.fuzzy_edits = cfg.fuzzy_edits
        pov = validator.prepare_pov() if cfg.pov else {"usable": False, "reason": "disabled"}
        graph_ref = validator.prepare_graph_reference() if before else {}
        row["paths_removed_by_real_fix"] = len(graph_ref.get("removed_by_real_fix") or [])
        cq = None
        if cfg.codeql:
            from .codeql_oracle import CodeQLOracle
            cq = CodeQLOracle(cfg.codeql, ws, cve, builder.state_dir, cfg.codeql_timeout)
            ref = cq.prepare_reference()
            row["codeql_paths_removed_by_real_fix"] = len(ref.get("removed_by_real_fix") or [])
            if ref.get("error"):
                row["codeql_error"] = ref["error"][:300]
        row["pov_usable"] = pov.get("usable")
        row["pov_reason"] = pov.get("reason")
        file_ctx = agents.file_context(ws.path, cve)
        graph_ctx = agents.graph_context(ws.path, cve, before) if before else file_ctx
        row["file_context_chars"] = len(file_ctx)
        row["graph_context_chars"] = len(graph_ctx)

        verdict: Verdict | None = None
        if mode == "noop":
            verdict = validator.check()
        elif mode == "oracle":
            row["oracle_files"] = ws.apply_reference_fix()
            verdict = validator.check()
        elif mode == "rule":
            reply = rule_patch(ws.path, cve.cwe, before)
            transcript.append({"role": "rule", "prompt": "", "reply": reply})
            row["iterations"] = 1
            verdict = _apply_and_check(ws, reply, validator, art, 1, row)
        elif mode == "single":
            reply = _ask(cfg.llm, "coder", agents.single_prompt(cve, file_ctx), transcript)
            row["iterations"] = 1
            verdict = _apply_and_check(ws, reply, validator, art, 1, row)
        else:
            ctx_kind, path_gate, multi = LOOP_MODES[mode]
            ctx = graph_ctx if ctx_kind == "graph" else file_ctx
            row["context_chars"] = len(ctx)
            plan = ""
            # seeded: the rule's patch is the first candidate and costs no model call; it counts against the budget
            seed = rule_patch(ws.path, cve.cwe, before) if mode == "seeded" else ""
            row["seeded"] = bool(seed) if mode == "seeded" else None
            if multi and not seed:
                plan = _ask(cfg.llm, "planner", agents.planner_prompt(cve, ctx), transcript)
                (art / "plan.md").write_text(plan, encoding="utf-8")
            critique, prev = "", ""
            for it in range(1, cfg.max_iters + 1):
                row["iterations"] = it
                ws.reset()
                if it == 1 and seed:
                    reply = seed
                    transcript.append({"role": "rule", "prompt": "", "reply": reply})
                else:
                    if multi and not plan:
                        plan = _ask(cfg.llm, "planner", agents.planner_prompt(cve, ctx), transcript)
                        (art / "plan.md").write_text(plan, encoding="utf-8")
                    reply = _ask(cfg.llm, "coder", agents.coder_prompt(cve, ctx, plan, critique, prev,
                                                                        prev_by_rule=bool(seed) and it == 2), transcript)
                verdict = _apply_and_check(ws, reply, validator, art, it, row)
                if Validator.loop_accepts(verdict, use_graph=path_gate) or it == cfg.max_iters:
                    break
                prev = (art / f"patch_{it}.diff").read_text(encoding="utf-8", errors="replace") if (art / f"patch_{it}.diff").exists() else ""
                fb = verdict.feedback if path_gate else _strip_graph(verdict)
                # the single-agent baseline gets the raw validator output instead of a Critic's analysis
                critique = _critic(cfg, cve, prev, fb, verdict, path_gate, transcript, row, art, it) if multi else fb
        if verdict is not None:
            verdict = validator.final(verdict, pov, graph_ref, cq)  # held-out oracles, run once on the final patch
            (art / "verdict_final.json").write_text(json.dumps(verdict.to_dict(), indent=2), encoding="utf-8")
        row.update(_verdict_fields(verdict))
        if ws:
            (art / "final.diff").write_text(ws.diff(), encoding="utf-8")
    except StopRun:
        raise
    except LLMError as e:
        row.update(status="error", stage="llm", error=str(e)[:500])
    except Exception as e:
        row.update(status="error", error=f"{type(e).__name__}: {e}"[:500])
        (art / "traceback.txt").write_text(traceback.format_exc(), encoding="utf-8")
    finally:
        if ws and ws.path.exists():
            try:
                ws.reset()
            except Exception:
                pass
    return _finish(row, t0, art, transcript, cfg.llm if mode in LLM_MODES else None)


# ------------------------------------------------------------------ helpers

def _ask(llm: LLM | None, role: str, prompt: str, transcript: list) -> str:
    if llm is None:
        raise LLMError("this mode needs a model: pass --provider/--model and set the API key")
    reply = llm.chat(agents.SYSTEM, prompt, role=role)
    transcript.append({"role": role, "prompt": prompt, "reply": reply})
    return reply


def _critic(cfg: Config, cve: CVE, diff: str, feedback: str, verdict: Verdict, path_gate: bool,
            transcript: list, row: dict, art: Path, it: int) -> str:
    """Ask the Critic for a JSON critique, check it, and return the text the Coder reads.
    A reply that is not valid JSON is passed on as it is and counted, so a run never stops on it."""
    reply = _ask(cfg.llm, "critic", agents.critic_prompt(cve, diff, feedback, structured=cfg.structured_critic), transcript)
    if not cfg.structured_critic:
        return reply
    row["critic_calls"] = row.get("critic_calls", 0) + 1
    crit, why = agents.parse_critique(reply)
    record = {"iteration": it, "valid": crit is not None, "error": why, "critique": crit}
    if crit is None:
        row["critic_invalid"] = row.get("critic_invalid", 0) + 1
        (art / f"critique_{it}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
        return reply
    cov = agents.critique_coverage(crit, verdict.remaining if path_gate else [])
    record["path_coverage"] = cov
    if cov is not None:
        row.setdefault("critic_path_coverage", []).append(round(cov, 2))
    (art / f"critique_{it}.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
    return agents.render_critique(crit)


def _apply_and_check(ws: Workspace, reply: str, validator: Validator, art: Path, it: int,
                     row: dict | None = None) -> Verdict:
    edits = parse_edits(reply)
    if not edits:
        v = Verdict("rejected", "no_edits", paths_before=len(validator.paths_before),
                    feedback="The reply contained no edit blocks in the required SEARCH/REPLACE format.")
        (art / f"verdict_{it}.json").write_text(json.dumps(v.to_dict(), indent=2), encoding="utf-8")
        return v
    fuzzy: list[str] = []
    errors = apply_edits(ws.path, edits, fuzzy_log=fuzzy, fuzzy=getattr(validator, "fuzzy_edits", True))
    if fuzzy and row is not None:
        row["fuzzy_edits"] = row.get("fuzzy_edits", 0) + len(fuzzy)
        (art / f"fuzzy_{it}.txt").write_text("\n".join(fuzzy), encoding="utf-8")
    if reply.count("<<<<<<< SEARCH") > len(edits):
        errors.append("The reply was cut off or malformed: some edit blocks are incomplete. Keep the patch short.")
    diff = ws.diff()
    (art / f"patch_{it}.diff").write_text(diff, encoding="utf-8")
    if errors:
        v = Verdict("rejected", "apply", paths_before=len(validator.paths_before),
                    feedback=(f"{len(errors)} of {len(edits)} edit blocks could not be applied, so the whole patch "
                              "was discarded. Copy SEARCH lines exactly from the code shown.\n\n" + "\n\n".join(errors)))
        (art / f"verdict_{it}.json").write_text(json.dumps(v.to_dict(), indent=2), encoding="utf-8")
        return v
    v = validator.check()
    (art / f"verdict_{it}.json").write_text(json.dumps(v.to_dict(), indent=2), encoding="utf-8")
    return v


def _strip_graph(v: Verdict) -> str:
    """No-graph ablation: the critic only sees build and test output."""
    return "" if v.stage == "graph" else v.feedback


def _verdict_fields(v: Verdict | None) -> dict:
    if v is None:
        return {}
    t = v.tests or {}
    return {"status": v.status, "stage": v.stage, "paths_after": v.paths_after,
            "graph_ok": v.graph_ok, "graph_eval_ok": v.graph_eval_ok, "pov_ok": v.pov_ok, "codeql_ok": v.codeql_ok,
            "compile_ok": bool(v.compile and v.compile.get("ok")),
            "tests_run": t.get("tests_run"), "new_test_failures": len(t.get("new_failures") or []),
            "deleted_targets": ";".join(v.deleted_targets)}


def _finish(row: dict, t0: float, art: Path, transcript: list, llm: LLM | None = None) -> dict:
    row["seconds"] = round(time.time() - t0, 1)
    if llm is not None:
        row.update(llm_calls=llm.usage.calls, prompt_tokens=llm.usage.prompt_tokens,
                   completion_tokens=llm.usage.completion_tokens)
        llm.usage = type(llm.usage)()  # reset per CVE
    (art / "result.json").write_text(json.dumps(row, indent=2, default=str), encoding="utf-8")
    if transcript:
        (art / "transcript.json").write_text(json.dumps(transcript, indent=2), encoding="utf-8")
    return row
