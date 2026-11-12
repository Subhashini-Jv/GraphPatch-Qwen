"""Planner, Coder and Critic prompts, and the code context they see."""

from __future__ import annotations

import json
import re
from pathlib import Path

from .dataset import CVE
from .javasrc import MethodInfo, methods_in, numbered, read
from .taint import Finding

CWE_ADVICE = {
    "CWE-022": "Resolve the final path (getCanonicalPath / toRealPath / normalize) and reject it unless it stays inside the intended base directory; reject '..' and absolute paths in names taken from input or archive entries.",
    "CWE-078": "Do not pass untrusted text to a shell. Use an argument list, validate against an allow-list, and never concatenate input into a command string.",
    "CWE-079": "HTML-encode untrusted data at the point it is written into HTML (or use the framework's escaping helper); do not remove functionality.",
    "CWE-094": "Never evaluate untrusted text as code or expressions. Use a restricted evaluation context, an allow-list, or treat input as a literal.",
}

EDIT_RULES = """Reply with one or more edit blocks in exactly this format and nothing else outside them:

FILE: path/relative/to/repo/File.java
<<<<<<< SEARCH
exact lines copied from the current file (include enough lines to be unique)
=======
the replacement lines
>>>>>>> REPLACE

Rules:
- SEARCH must match the current file text exactly (without the line-number prefixes shown in the context).
- Keep the change minimal. Do not delete the vulnerable feature; make it safe.
- Every SEARCH block must be lines that appear one after another in the context above. Never anchor on a lone `}` or on lines you have not seen together.
- To add a new helper method, use the first line(s) of a method shown above as SEARCH, and in REPLACE put the new method followed by those same lines unchanged.
- Add imports with a separate edit block when you use a new class.
- If you call a new method, the same reply must contain the edit that defines it.
- Java source level may be as old as Java 8: no `var`, records, text blocks or newer APIs.
"""


# ------------------------------------------------------------------ context

def _header(text: str) -> str:
    out = []
    for line in text.split("\n"):
        out.append(line)
        if line.lstrip().startswith(("public class", "class ", "public final class", "final class", "public abstract class", "abstract class", "public interface", "interface ", "public enum", "enum ")):
            break
        if len(out) > 60:
            break
    return "\n".join(out)


def graph_context(repo: Path, cve: CVE, findings: list[Finding], max_methods: int = 12) -> str:
    """Only the taint paths and the methods they pass through."""
    parts = ["TAINT PATHS FOUND BY THE CODE GRAPH (untrusted source -> dangerous sink):\n"]
    parts += [f.render() + "\n" for f in findings[:8]]
    wanted: dict[str, set[tuple[str, str]]] = {}
    for f in findings[:8]:
        wanted.setdefault(f.file, set()).add((f.cls, f.method))
    for r in cve.main_fix_rows:
        if r.get("method"):
            wanted.setdefault(r["file"], set()).add((r["class"], r["method"]))
    shown = 0
    for file, keys in wanted.items():
        p = Path(repo) / file
        if not p.exists():
            continue
        text = read(p)
        ms = [m for m in methods_in(text, file) if (m.cls, m.name) in keys]
        if not ms:
            continue
        parts.append(f"\n===== {file} (imports and class header) =====\n{_header(text)}\n")
        for m in ms:
            if shown >= max_methods:
                break
            parts.append(f"----- {m.cls}.{m.name} (lines {m.start}-{m.end}) -----\n{numbered(text, m.start, m.end)}\n")
            shown += 1
        lines = text.split("\n")
        fields = [f"{i + 1:5d}  {l}" for i, l in enumerate(lines)
                  if l.strip().startswith(("private ", "protected ", "public ", "final ")) and ";" in l and "(" not in l][:15]
        if fields:
            parts.append("field declarations (single lines from different places in the file, NOT consecutive; "
                         "never use them as a SEARCH block):\n" + "\n".join(fields) + "\n")
    return "\n".join(parts)


def file_context(repo: Path, cve: CVE, max_lines: int = 1500) -> str:
    """Whole vulnerable files: what a plain LLM baseline would be given."""
    parts = []
    for file in cve.target_files:
        p = Path(repo) / file
        if not p.exists():
            continue
        text = read(p)
        n = len(text.split("\n"))
        parts.append(f"===== {file} ({n} lines) =====\n{numbered(text, 1, min(n, max_lines))}\n")
    return "\n".join(parts)


def cve_brief(cve: CVE) -> str:
    methods = sorted({f"{r['class']}.{r['method']}" for r in cve.main_fix_rows if r.get("method")})
    return (f"{cve.cve_id} ({cve.cwe} {cve.cwe_name}) in {cve.repo_url}\n"
            f"Advisory: {cve.summary.strip()[:1500]}\n"
            f"Vulnerable methods (from the benchmark): {', '.join(methods) or 'see files'}\n"
            f"Files: {', '.join(cve.target_files)}")


# ------------------------------------------------------------------ prompts

SYSTEM = "You are a senior Java security engineer fixing a known vulnerability with a minimal, safe patch."


def planner_prompt(cve: CVE, context: str) -> str:
    return f"""{cve_brief(cve)}

Fix guidance for {cve.cwe}: {CWE_ADVICE.get(cve.cwe, '')}

CODE CONTEXT:
{context}

Write a short remediation plan (at most 8 bullet points): where untrusted data enters, which call is dangerous,
exactly which method(s) and lines to change, the check or encoding to add, and what behaviour must stay the same.
Do not write code."""


def coder_prompt(cve: CVE, context: str, plan: str, critique: str = "", previous_diff: str = "",
                 prev_by_rule: bool = False) -> str:
    retry = ""
    if critique:
        who = ("A RULE-BASED PATCH (a fixed containment check, not written by you; already reverted). Keep what is right "
               "in it, fix what the review below names, and write the complete patch against the original code:"
               if prev_by_rule else
               "YOUR PREVIOUS PATCH (already reverted; write the complete patch again against the original code):")
        retry = f"""
{who}
{previous_diff[:6000] or '(no changes were applied)'}

WHY IT WAS REJECTED:
{critique}
"""
    plan_part = f"\nPLAN:\n{plan}\n" if plan else ""
    return f"""{cve_brief(cve)}
{plan_part}
CODE CONTEXT (line numbers are for reference only):
{context}
{retry}
{EDIT_RULES}"""


def single_prompt(cve: CVE, context: str) -> str:
    return f"""{cve_brief(cve)}

CODE:
{context}

Fix the vulnerability.
{EDIT_RULES}"""


CRITIC_FORMAT = """Reply with ONE JSON object and nothing else, in exactly this shape:
{
  "root_cause": "two sentences on why the patch was rejected",
  "instructions": [
    {"file": "path/relative/to/repo/File.java", "method": "methodName", "line": 123,
     "variable": "name of the tainted variable or null", "action": "what the next patch must do here"}
  ]
}
Rules: 1 to 6 instructions; "line" is a line number of the ORIGINAL code or null; if untrusted data still
reaches a sink, there must be an instruction for each surviving path naming its method, variable and line.
Do not write the patch."""


def critic_prompt(cve: CVE, diff: str, feedback: str, structured: bool = True) -> str:
    head = f"""{cve_brief(cve)}

A candidate patch was rejected by the validator.

PATCH:
{diff[:8000] or '(the edits could not be applied)'}

VALIDATOR OUTPUT:
{feedback[:6000]}
"""
    if structured:
        return head + "\n" + CRITIC_FORMAT
    return head + """
Explain the root cause in two sentences, then give concrete instructions (at most 6 bullets) for the next patch.
If untrusted data still reaches a sink, name the exact variable and line where the check must be added.
Do not write the full patch."""


# ------------------------------------------------------------------ structured critique

PATH_RE = re.compile(r"\[CWE-\d+\] (?P<cls>[\w$]+)\.(?P<method>[\w$<>]+) line (?P<line>\d+)")


def parse_critique(reply: str) -> tuple[dict | None, str]:
    """The Critic's JSON, checked against the schema. Returns (critique, "") or (None, reason)."""
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", (reply or "").strip())
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        return None, "no JSON object in the reply"
    try:
        data = json.loads(text[start:end + 1])
    except json.JSONDecodeError as e:
        return None, f"invalid JSON: {e.msg}"
    if not isinstance(data, dict):
        return None, "the JSON is not an object"
    cause = data.get("root_cause")
    steps = data.get("instructions")
    if not isinstance(cause, str) or not cause.strip():
        return None, "missing root_cause"
    if not isinstance(steps, list) or not 1 <= len(steps) <= 6:
        return None, "instructions must be a list of 1 to 6 items"
    clean = []
    for st in steps:
        if not isinstance(st, dict) or not isinstance(st.get("action"), str) or not st["action"].strip():
            return None, "every instruction needs an action"
        line = st.get("line")
        if isinstance(line, str) and line.strip().isdigit():
            line = int(line)
        clean.append({"file": str(st.get("file") or ""), "method": str(st.get("method") or ""),
                      "line": line if isinstance(line, int) else None,
                      "variable": str(st.get("variable") or "") if st.get("variable") else "",
                      "action": st["action"].strip()})
    return {"root_cause": cause.strip(), "instructions": clean}, ""


def render_critique(c: dict) -> str:
    """The checked critique as the text the Coder reads."""
    out = [f"Root cause: {c['root_cause']}", "Instructions:"]
    for i, st in enumerate(c["instructions"], 1):
        where = ", ".join(x for x in (st["file"], st["method"] and f"method {st['method']}",
                                      st["line"] and f"line {st['line']}",
                                      st["variable"] and f"variable `{st['variable']}`") if x)
        out.append(f"{i}. {st['action']}" + (f"  [{where}]" if where else ""))
    return "\n".join(out)


def critique_coverage(c: dict, remaining: list[str]) -> float | None:
    """Share of the surviving taint paths that some instruction addresses by method name.
    None when no path survived (the patch failed an earlier gate)."""
    paths = {(m["cls"], m["method"]) for r in remaining for m in [PATH_RE.search(r)] if m}
    if not paths:
        return None
    named = {st["method"] for st in c["instructions"] if st["method"]}
    named |= {st["method"].split(".")[-1] for st in c["instructions"] if "." in st["method"]}
    return sum(1 for _, meth in paths if meth in named) / len(paths)
