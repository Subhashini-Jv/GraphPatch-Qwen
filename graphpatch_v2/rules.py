"""Rule-based repair (no language model): the `rule` baseline mode.

For path traversal (CWE-22) it inserts the standard containment check after the
tainted `File` is built, or before the dangerous call when no base directory is
known:

    if (!Paths.get(String.valueOf(file)).toAbsolutePath().normalize()
            .startsWith(Paths.get(String.valueOf(baseDir)).toAbsolutePath().normalize())) {
        throw new SecurityException("Blocked path outside the target directory: " + file);
    }

The edit is written as ordinary SEARCH/REPLACE blocks, so it goes through exactly
the same apply, build, test, path and held-out checks as the model's patches.
Other CWEs have no rule; the mode then reports "no edits".
"""

from __future__ import annotations

import re
from pathlib import Path

from .javasrc import methods_in
from .taint import Finding

ASSIGN_STEP = re.compile(r"^`(?P<var>[A-Za-z_]\w*)` = \.\.\. \(line (?P<line>\d+)\)")
RECEIVER_SINK = re.compile(r"^(?P<var>[A-Za-z_]\w*)\.\w+\(")
NEW_FILE = r"new\s+(?:java\.io\.)?File\s*\("
# a File built from (base, name): new File(dir, name) or a resolver such as FileUtils.resolveFile(dir, name)
BUILDER = rf"(?:{NEW_FILE}|[A-Za-z_][\w.]*\.(?:resolve\w*|\w*File)\s*\()"
SKIP_RECEIVERS = ("this", "super")


def _split_args(text: str, start: int) -> tuple[list[str], int] | None:
    """Arguments of the call whose '(' is at text[start]; returns (args, index after ')')."""
    depth, cur, args, i, quote = 0, "", [], start, None
    while i < len(text):
        ch = text[i]
        if quote:
            cur += ch
            if ch == "\\" and i + 1 < len(text):
                cur += text[i + 1]
                i += 1
            elif ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
            cur += ch
        elif ch == "(":
            depth += 1
            if depth > 1:
                cur += ch
        elif ch == ")":
            depth -= 1
            if depth == 0:
                if cur.strip():
                    args.append(cur.strip())
                return args, i + 1
            cur += ch
        elif ch == "," and depth == 1:
            args.append(cur.strip())
            cur = ""
        else:
            cur += ch
        i += 1
    return None


def _statement_end(lines: list[str], first: int) -> int:
    """Index of the line that ends the statement starting at lines[first] (first ';' outside brackets)."""
    depth = 0
    for i in range(first, min(len(lines), first + 15)):
        for ch in re.sub(r'"(?:\\.|[^"\\])*"', '""', lines[i]):
            if ch in "([{":
                depth += 1
            elif ch in ")]}":
                depth -= 1
            elif ch == ";" and depth <= 0:
                return i
    return first


def _statement_start(lines: list[str], idx: int) -> int:
    """Index of the first line of the statement that contains lines[idx]."""
    i = idx
    while i > 0:
        prev = lines[i - 1].split("//")[0].rstrip()
        if not prev or prev.endswith((";", "{", "}")) or prev.lstrip().startswith(("@", "*", "/*")):
            break
        i -= 1
    return i


def _method_start(meths: list, line: int) -> int:
    """Index of the first line of the innermost method that contains 1-based `line` (0 when none)."""
    inside = [m for m in meths if m.start <= line <= m.end]
    return min(inside, key=lambda m: m.end - m.start).start - 1 if inside else 0


def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _guard(var: str, base: str | None, indent: str, step: str) -> list[str]:
    if base:
        cond = (f"!java.nio.file.Paths.get(String.valueOf({var})).toAbsolutePath().normalize()"
                f".startsWith(java.nio.file.Paths.get(String.valueOf({base})).toAbsolutePath().normalize())")
        msg = "Blocked path outside the target directory: "
    else:
        cond = f"String.valueOf({var}).contains(\"..\")"
        msg = "Blocked path with '..': "
    return [f"{indent}if ({cond}) {{",
            f"{indent}{step}throw new SecurityException(\"{msg}\" + {var});",
            f"{indent}}}"]


def _plan(lines: list[str], f: Finding, meths: list) -> tuple[int, str, str | None, int] | None:
    """(insert after line index, variable, base directory or None, line whose indent to use) for one finding."""
    sink_idx = f.line - 1
    steps = [str(s) for s in f.steps]
    var, decl_line = None, None

    def builder(v: str) -> re.Pattern:
        return re.compile(rf"\b{re.escape(v)}\s*=\s*{BUILDER}")

    # 1) the first variable on the path that is built from a base directory, so one guard covers
    #    everything derived from it (dirF = f.getParentFile() ...)
    for s in steps:
        m = ASSIGN_STEP.match(s)
        if m and 0 < int(m["line"]) <= len(lines) and builder(m["var"]).search(lines[int(m["line"]) - 1]):
            var, decl_line = m["var"], int(m["line"])
            break
    # 2) the receiver of the sink call: fileDir.mkdir() (not a class such as IOUtil.copy)
    if var is None:
        m = RECEIVER_SINK.match(f.sink)
        if m and m["var"] not in SKIP_RECEIVERS and not m["var"][0].isupper():
            var = m["var"]
    # 3) the last tainted variable on the path
    if var is None:
        for s in steps:
            m = ASSIGN_STEP.match(s)
            if m:
                var, decl_line = m["var"], int(m["line"])
    if var is None:
        return None
    # only guard values that are paths: a File, Path or String declared in the method that holds the sink
    typed = re.compile(rf"\b(?:File|Path|String)\s+{re.escape(var)}\b")
    where = decl_line or f.line
    if not any(typed.search(l) for l in lines[_method_start(meths, where):where]):
        return None
    decl = builder(var)
    lo = max(0, sink_idx - 200)
    cands = [decl_line - 1] if decl_line and decl.search(lines[decl_line - 1]) else []
    cands += [i for i in range(min(sink_idx, len(lines) - 1), lo - 1, -1) if decl.search(lines[i])]
    if cands:
        d = cands[0]
        text = "\n".join(lines[d:d + 15])
        m = decl.search(text)
        parsed = _split_args(text, m.end() - 1)
        if parsed:
            args, _ = parsed
            base = args[0] if len(args) == 2 else None
            return _statement_end(lines, d), var, base, d
        return _statement_end(lines, d), var, None, d
    # no constructor found: check just before the statement with the dangerous call
    start = _statement_start(lines, sink_idx)
    return start - 1, var, None, start


def _unique_search(lines: list[str], first: int, last: int) -> tuple[int, int]:
    """Grow lines[first..last] upwards until the block occurs once in the file."""
    text = "\n".join(lines)
    while True:
        block = "\n".join(lines[first:last + 1])
        if text.count(block) == 1 or first == 0:
            return first, last
        first -= 1


def rule_patch(repo: Path, cwe: str, findings: list[Finding]) -> str:
    """SEARCH/REPLACE blocks that guard every finding, or "" when no rule applies."""
    if cwe != "CWE-022":
        return ""
    blocks = []
    by_file: dict[str, list[Finding]] = {}
    for f in findings:
        by_file.setdefault(f.file, []).append(f)
    for rel, fs in by_file.items():
        lines = (Path(repo) / rel).read_text(encoding="utf-8", errors="replace").split("\n")
        meths = methods_in("\n".join(lines), rel)
        plans = {}
        for f in fs:
            p = _plan(lines, f, meths)
            if p and (p[0], p[1]) not in plans:
                plans[(p[0], p[1])] = p
        # insert from the bottom up so earlier line numbers stay valid, writing each block against the
        # text as it is at that moment (blocks are applied in this order)
        for n, (after, var, base, ind) in enumerate(sorted(plans.values(), key=lambda p: -p[0])):
            indent = _indent(lines[ind])
            step = "\t" if indent.startswith("\t") else "    "
            if base and re.search(rf"\b{re.escape(var)}\b", base):
                # the statement overwrites the base (file = new File(file, name)): remember it first
                snap = f"gpBaseDir{n}"
                guard = _guard(var, snap, indent, step)
                first, last = _unique_search(lines, ind, after)
                new = lines[first:ind] + [f"{indent}final Object {snap} = {base};"] + lines[ind:last + 1] + guard
            elif after < 0:
                guard = _guard(var, base, indent, step)
                first, last = _unique_search(lines, 0, 0)
                new = guard + lines[first:last + 1]
            else:
                guard = _guard(var, base, indent, step)
                first, last = _unique_search(lines, after, after)
                new = lines[first:last + 1] + guard
            blocks.append(f"FILE: {rel}\n<<<<<<< SEARCH\n" + "\n".join(lines[first:last + 1]) +
                          "\n=======\n" + "\n".join(new) + "\n>>>>>>> REPLACE")
            lines[first:last + 1] = new
    return "\n\n".join(blocks)
