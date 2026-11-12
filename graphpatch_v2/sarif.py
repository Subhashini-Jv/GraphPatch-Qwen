"""Export GraphPatch scan findings as SARIF 2.1.0, the format GitHub code scanning reads.

  python -m graphpatch_v2.sarif <project folder> --out graphpatch.sarif [--cwe all|CWE-022|...] [--fail-on-findings]

Each taint path becomes one result at its sink, with the whole source-to-sink path in the message. No
language model and no API key are needed. See .github/workflows/graphpatch.yml for the GitHub Action.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .scanner import CWE_NAMES, java_files, risk, scan_repo
from .taint import SINKS, Finding

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
# GitHub turns security-severity into Critical/High/Medium/Low in the Security tab
SEVERITY = {"CWE-022": "7.5", "CWE-078": "9.8", "CWE-079": "6.1", "CWE-094": "9.8"}


def _rule(cwe: str) -> dict:
    num = cwe.split("-")[1].lstrip("0")
    name = CWE_NAMES.get(cwe, cwe)
    return {
        "id": f"graphpatch/{cwe}",
        "name": name.replace(" ", ""),
        "shortDescription": {"text": f"{name} ({cwe})"},
        "fullDescription": {"text": f"Untrusted input reaches a dangerous call without a check that removes the risk ({name})."},
        "helpUri": f"https://cwe.mitre.org/data/definitions/{num}.html",
        "help": {"text": f"GraphPatch found a source-to-sink taint path for {cwe}. Add a check on the path "
                         "(for path traversal: normalise the path and verify it stays inside the target directory)."},
        "defaultConfiguration": {"level": "error"},
        "properties": {"tags": ["security", f"external/cwe/cwe-{int(num):03d}"],
                       "security-severity": SEVERITY.get(cwe, "7.0"), "precision": "medium"},
    }


def _result(f: Finding, rule_index: int, prefix: str = "") -> dict:
    steps = "\n".join(f"{i + 1}. {s}" for i, s in enumerate(f.steps))
    return {
        "ruleId": f"graphpatch/{f.cwe}",
        "ruleIndex": rule_index,
        "level": "error",
        "message": {"text": f"Tainted data reaches `{f.sink}` in {f.cls}.{f.method}. Path:\n{steps}"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": prefix + f.file},
            "region": {"startLine": max(1, f.line)}}}],
        "partialFingerprints": {"graphpatchPath/v1": f.key},
        "properties": {"graphpatch-risk": risk(f)["score"]},
    }


def to_sarif(findings: list[Finding], cwes: list[str], prefix: str = "") -> dict:
    rules = [_rule(c) for c in cwes]
    index = {c: i for i, c in enumerate(cwes)}
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "GraphPatch", "semanticVersion": __version__.lstrip("v") + ".0",
                                "rules": rules}},
            "results": [_result(f, index[f.cwe], prefix) for f in findings if f.cwe in index],
        }],
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m graphpatch_v2.sarif", description=__doc__.split("\n\n")[0])
    ap.add_argument("project", type=Path, help="folder of the Java project to scan")
    ap.add_argument("--out", type=Path, default=Path("graphpatch.sarif"))
    ap.add_argument("--cwe", default="all", help="all, or one of " + ", ".join(CWE_NAMES))
    ap.add_argument("--fail-on-findings", action="store_true", help="exit with code 1 when anything is found")
    a = ap.parse_args(argv)
    cwes = list(CWE_NAMES) if a.cwe == "all" else [a.cwe]
    if any(c not in SINKS for c in cwes):
        ap.error(f"unknown CWE {a.cwe}")
    findings = scan_repo(a.project, cwes)
    # GitHub needs paths relative to the repository root (the folder the command runs in)
    try:
        prefix = a.project.resolve().relative_to(Path.cwd().resolve()).as_posix() + "/"
    except ValueError:
        prefix = ""
    prefix = "" if prefix == "./" else prefix
    a.out.write_text(json.dumps(to_sarif(findings, cwes, prefix), indent=2), encoding="utf-8")
    print(f"GraphPatch {__version__}: {len(java_files(a.project))} Java files, {len(findings)} findings -> {a.out}")
    return 1 if findings and a.fail_on_findings else 0


if __name__ == "__main__":
    sys.exit(main())
