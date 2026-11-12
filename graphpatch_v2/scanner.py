"""Whole-project scan: every taint path in a Java, Python or JavaScript project (web app, SARIF, CLI tools).

Java goes through taint.py (the paper's analysis); Python and JavaScript through polyglot.py (Tree-sitter)."""

from __future__ import annotations

import re
from pathlib import Path

from .taint import Finding, TargetSpec, find_paths

MAX_FILES = 1500
CWE_NAMES = {"CWE-022": "Path traversal", "CWE-078": "OS command injection",
             "CWE-079": "Cross-site scripting", "CWE-094": "Code injection"}


# The per-CWE sink lists in taint.py are wide on purpose: in the benchmark the vulnerable method is known, so a
# generic name such as process() or getValue() is a sink only there. In a whole-project scan the same names match
# ordinary code, so for CWE-78/79/94 a finding must start at real untrusted input (a request, an archive entry,
# not just any public-method parameter) and, for CWE-78/94, end in a call that really runs a command or code.
STRONG_SINKS = {
    "CWE-078": re.compile(r"(^|\.)(exec|command|start)\(|ProcessBuilder|(?i:cmd|command)\w*\.addArguments?\(|(?i:executor)\w*\.execute\("),
    # console and log output is not a web page
    "CWE-079": re.compile(r"^(?!(System\.(out|err)|(?i:log|logger))\.)"),
    "CWE-094": re.compile(r"(^|\.)(eval|evaluate|parseExpression|parseClass|executeExpression|compileExpression|"
                          r"createValueExpression|createMethodExpression|buildConstraintViolationWithTemplate|"
                          r"createTemplate|parseScript|runScript|evaluateExpression|mergeTemplate)\(|"
                          r"GroovyShell|ScriptEngineManager|SpelExpressionParser|new Template\("),
}


def _real_finding(f: Finding) -> bool:
    if f.cwe == "CWE-022":
        return True
    if str(f.steps[0]).startswith("parameter "):
        return False
    if not f.file.endswith(".java"):
        return True  # the Python/JS catalogues list only calls that really run commands or code
    strong = STRONG_SINKS.get(f.cwe)
    return strong is None or bool(strong.search(f.sink))


def java_files(repo: Path) -> list[str]:
    """Main-source .java files of a project (tests left out), repo-relative."""
    files = []
    for p in sorted(Path(repo).rglob("*.java")):
        rel = p.relative_to(repo).as_posix()
        if "/test/" in f"/{rel}" or rel.endswith("Test.java") or "/." in f"/{rel}":  # tests, hidden folders
            continue
        files.append(rel)
    return files[:MAX_FILES]


def source_files(repo: Path) -> dict[str, list[str]]:
    """Analysable files per language: {"java": [...], "python": [...], "javascript": [...]}."""
    from . import polyglot
    out = {"java": java_files(repo)}
    for lang in polyglot.LANGUAGES:
        out[lang] = polyglot.source_files(repo, lang, MAX_FILES)
    return out


def scan_repo(repo: Path, cwes: list[str], languages: dict[str, list[str]] | None = None) -> list[Finding]:
    from . import polyglot
    by_lang = languages or source_files(repo)
    files = by_lang.get("java", [])
    found: list[Finding] = []
    for cwe in cwes:
        # every public method is an entry point of an uploaded library, so its String parameters count as input
        spec = TargetSpec(cwe, files, {(f, "", None) for f in files})
        found += find_paths(repo, spec) if files else []
    for lang in polyglot.LANGUAGES:
        if by_lang.get(lang):
            found += polyglot.find_paths(repo, by_lang[lang], cwes, lang)
    # "return from getX()" sinks only matter when a CVE says that value ends up in a web page;
    # in a whole-project scan they flag every getter, so leave them out
    found = [f for f in found if not f.sink.startswith("return from ") and _real_finding(f)]
    # paths that start at real input (archive entry names, requests) first, public-method parameters after
    found.sort(key=lambda f: (str(f.steps[0]).startswith("parameter "), f.cwe, f.file, f.line))
    return found


# ------------------------------------------------------------------ risk score

BASE_RISK = {"CWE-078": 80, "CWE-094": 75, "CWE-022": 65, "CWE-079": 55}
DESTRUCTIVE = re.compile(r"FileOutputStream|FileWriter|RandomAccessFile|delete|renameTo|write|copy|move|exec|"
                         r"ProcessBuilder|eval|parseExpression|mkdirs?\(|"
                         # Python / JavaScript
                         r"system|popen|subprocess|spawn|unlink|remove|rmtree|rmSync|\bopen\(|send_?[fF]ile|innerHTML|Function\(")


def risk(f: Finding) -> dict:
    """A simple, explainable 0-100 score to sort findings: the kind of bug, where the input comes from, what the
    dangerous call does and how direct the path is. A triage aid, not a measured probability."""
    score, why = BASE_RISK.get(f.cwe, 50), [f"{f.cwe} base {BASE_RISK.get(f.cwe, 50)}"]
    src = str(f.steps[0]) if f.steps else ""
    if src.startswith("untrusted input") or src.startswith("archive entry name"):
        score += 15
        why.append("+15 real untrusted input (request or archive entry)")
    elif src.startswith("parameter "):
        score -= 10
        why.append("-10 input is only a public-method parameter")
    if DESTRUCTIVE.search(f.sink):
        score += 10
        why.append("+10 the call writes, deletes or runs something")
    hops = sum(1 for s in f.steps if not str(s).startswith("SINK"))
    if hops <= 4:
        score += 5
        why.append("+5 short, direct path")
    elif hops > 10:
        score -= 5
        why.append("-5 long path through many steps")
    score = max(0, min(100, score))
    level = "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 50 else "low"
    return {"score": score, "level": level, "why": why}
