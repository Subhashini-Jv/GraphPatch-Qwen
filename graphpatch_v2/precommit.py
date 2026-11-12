"""Git pre-commit guard: block a commit whose staged Java files have taint findings.

    python -m graphpatch_v2.precommit [--all] [--cwe all|CWE-022 ...]
    python -m graphpatch_v2.precommit --install [--force]

The scan reads the working-tree copies of the files, not the staged blobs, so a file with unstaged edits is
checked as it is on disk. The whole project is scanned (calls between files matter) but only findings in
staged .java files are reported, unless --all is given.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

from .scanner import CWE_NAMES, scan_repo

HOOK = """#!/bin/sh
# GraphPatch pre-commit guard (python -m graphpatch_v2.precommit --install)
PY=python3
command -v "$PY" >/dev/null 2>&1 || PY=python
exec "$PY" -m graphpatch_v2.precommit
"""


def _git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True).stdout


def repo_root(cwd: Path | None = None) -> Path:
    return Path(_git("rev-parse", "--show-toplevel", cwd=cwd).strip())


def staged_java(root: Path) -> list[str]:
    out = _git("diff", "--cached", "--name-only", "--diff-filter=ACM", "-z", cwd=root)
    return sorted(p for p in out.split("\0") if p.endswith(".java"))


def install(root: Path, force: bool = False) -> int:
    hooks = Path(_git("rev-parse", "--git-path", "hooks", cwd=root).strip())
    hooks = hooks if hooks.is_absolute() else root / hooks
    hook = hooks / "pre-commit"
    if hook.exists() and hook.read_text(encoding="utf-8", errors="replace") != HOOK and not force:
        print(f"{hook} already exists; use --force to replace it", file=sys.stderr)
        return 1
    hooks.mkdir(parents=True, exist_ok=True)
    hook.write_bytes(HOOK.encode())  # LF line endings, also on Windows (Git for Windows runs it with its sh)
    hook.chmod(0o755)
    print(f"installed {hook}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m graphpatch_v2.precommit", description=__doc__.split("\n\n")[0])
    ap.add_argument("--all", action="store_true", help="report every finding in the project, not only staged files")
    ap.add_argument("--cwe", nargs="+", default=["all"], help="CWE ids to check (default: all)")
    ap.add_argument("--install", action="store_true", help="write .git/hooks/pre-commit")
    ap.add_argument("--force", action="store_true", help="with --install: replace an existing hook")
    a = ap.parse_args(argv)
    try:
        root = repo_root()
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("graphpatch precommit: not inside a git repository", file=sys.stderr)
        return 2
    if a.install:
        return install(root, a.force)
    cwes = sorted(CWE_NAMES) if "all" in a.cwe else [c.upper() for c in a.cwe]
    staged = set(staged_java(root))
    if not a.all and not staged:
        return 0
    findings = [f for f in scan_repo(root, cwes) if a.all or f.file in staged]
    for f in findings:
        print(f"{f.file}:{f.line}: {f.cwe} {CWE_NAMES.get(f.cwe, '')}: tainted data reaches `{f.sink}` "
              f"(in {f.cls}.{f.method}, from {f.steps[0] if f.steps else '?'})")
    if findings:
        print(f"graphpatch: {len(findings)} finding(s); fix them or commit with --no-verify", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
