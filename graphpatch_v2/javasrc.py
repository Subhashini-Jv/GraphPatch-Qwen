"""Java source helpers: parsing, method ranges, and search/replace edits."""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass
from pathlib import Path

import javalang


@dataclass
class MethodInfo:
    file: str          # path relative to repo root
    cls: str
    name: str
    params: list[str]
    start: int         # 1-based first line (declaration)
    end: int           # 1-based last line (closing brace)
    node: object       # javalang MethodDeclaration / ConstructorDeclaration

    @property
    def nparams(self) -> int:
        return len(self.params)


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def parse(text: str):
    """Parse Java source; returns the javalang CompilationUnit or None."""
    try:
        return javalang.parse.parse(text)
    except Exception:
        return None


def _match_brace_end(text: str, start_line: int) -> int:
    """Line of the brace closing the first '{' at or after start_line.

    Uses the javalang tokenizer so braces in strings/comments are ignored.
    """
    lines = text.split("\n")
    sub = "\n".join(lines[start_line - 1:])
    depth = 0
    try:
        for tok in javalang.tokenizer.tokenize(sub):
            if isinstance(tok, javalang.tokenizer.Separator):
                if tok.value == "{":
                    depth += 1
                elif tok.value == "}":
                    depth -= 1
                    if depth == 0:
                        return start_line + tok.position.line - 1
                elif tok.value == ";" and depth == 0:
                    return start_line + tok.position.line - 1  # abstract/interface method
    except Exception:
        pass
    return start_line


def methods_in(text: str, rel_file: str, tree=None) -> list[MethodInfo]:
    tree = tree or parse(text)
    if tree is None:
        return []
    out = []
    for _, cls in tree.filter(javalang.tree.TypeDeclaration):
        for m in list(cls.methods) + list(getattr(cls, "constructors", []) or []):
            if m.position is None:
                continue
            start = m.position.line
            # include annotations / javadoc-free start: javalang positions at the modifiers
            end = _match_brace_end(text, start)
            out.append(MethodInfo(rel_file, cls.name, m.name, [p.name for p in m.parameters], start, end, m))
    return out


def method_source(text: str, m: MethodInfo) -> str:
    lines = text.split("\n")
    return "\n".join(lines[m.start - 1:m.end])


def numbered(text: str, start: int, end: int) -> str:
    lines = text.split("\n")
    return "\n".join(f"{i:5d}  {lines[i - 1]}" for i in range(max(1, start), min(len(lines), end) + 1))


# ---------------------------------------------------------------- edits

EDIT_RE = re.compile(
    r"FILE:\s*(?P<file>\S+)\s*\n<<<<<<< SEARCH\n(?P<search>.*?)\n=======\n(?P<replace>.*?)\n>>>>>>> REPLACE",
    re.DOTALL,
)


@dataclass
class Edit:
    file: str
    search: str
    replace: str


BLOCK_RE = re.compile(r"<<<<<<< SEARCH\n(?P<search>.*?)\n=======\n(?P<replace>.*?)\n>>>>>>> REPLACE", re.DOTALL)
FILE_RE = re.compile(r"FILE:[ \t]*(?P<file>\S+)[ \t]*\n")


def parse_edits(reply: str) -> list[Edit]:
    """Edit blocks in reply order. A block without its own FILE: line belongs to the file named last.

    Models often write one FILE: line followed by several blocks for that file; until v2.16 those extra
    blocks were silently dropped and the patch was rejected as "cut off".
    """
    files = [(m.start(), m["file"].strip("`")) for m in FILE_RE.finditer(reply)]
    edits = []
    for m in BLOCK_RE.finditer(reply):
        named = [f for pos, f in files if pos < m.start()]
        if named:
            edits.append(Edit(named[-1], m["search"], m["replace"]))
    return edits


def _loose_find(haystack: str, needle: str):
    """Find needle ignoring differences in leading/trailing whitespace per line."""
    norm = lambda s: [l.strip() for l in s.split("\n")]
    hl, nl = haystack.split("\n"), norm(needle)
    while nl and not nl[0]:
        nl.pop(0)
    while nl and not nl[-1]:
        nl.pop()
    if not nl:
        return None
    hs = [l.strip() for l in hl]
    for i in range(len(hs) - len(nl) + 1):
        if hs[i:i + len(nl)] == nl:
            return i, i + len(nl)
    return None


FUZZY_MIN_RATIO = 0.90    # the best window must be at least this similar to the SEARCH block
FUZZY_MARGIN = 0.05       # and clearly better than any other window, or the match is ambiguous


def _fuzzy_find(haystack: str, needle: str):
    """Edit-distance match for a SEARCH block the model copied with small mistakes (a dropped `final`,
    a changed string literal, a renamed call). Compares the block with every window of the file with the
    same number of lines, ignoring indentation; returns the best window if it is
    similar enough and unique, else None. Aimed at the edit-format failures seen on CVE-2022-31194."""
    nl = [l.strip() for l in needle.split("\n")]
    while nl and not nl[0]:
        nl.pop(0)
    while nl and not nl[-1]:
        nl.pop()
    if len(nl) < 2:                      # one line is too little evidence to place an edit by similarity
        return None
    hs = [l.strip() for l in haystack.split("\n")]
    want = "\n".join(nl)
    first = difflib.SequenceMatcher(None, "", want, autojunk=False)
    scored = []
    # only windows with the same number of lines: a window with one line more would silently delete a
    # line the model never wrote into its REPLACE block
    for size in (len(nl),):
        for i in range(len(hs) - size + 1):
            window = "\n".join(hs[i:i + size])
            first.set_seq1(window)
            if first.real_quick_ratio() < FUZZY_MIN_RATIO or first.quick_ratio() < FUZZY_MIN_RATIO:
                continue
            scored.append((first.ratio(), i, i + size))
    if not scored:
        return None
    scored.sort(reverse=True)
    best = scored[0]
    if best[0] < FUZZY_MIN_RATIO:
        return None
    # a rival window that does not overlap the best one and is nearly as good makes the match ambiguous
    rivals = [r for r in scored[1:] if r[2] <= best[1] or r[1] >= best[2]]
    if rivals and best[0] - rivals[0][0] < FUZZY_MARGIN:
        return None
    return best[1], best[2], best[0]


def _near_miss(text: str, search: str) -> str:
    """Show what the file really contains where the SEARCH block starts, so the retry can copy it."""
    want = [l.strip() for l in search.split("\n") if l.strip()]
    if not want:
        return "The SEARCH block is empty."
    lines = text.split("\n")
    hits = [i for i, l in enumerate(lines) if l.strip() == want[0]]
    if not hits:
        return f"The line `{want[0]}` does not occur in the file."
    out = []
    for i in hits[:3]:
        out.append(f"The file around line {i + 1} actually reads:\n" + numbered(text, i + 1, i + len(want) + 2))
    return "\n".join(out)


def apply_edits(repo: Path, edits: list[Edit], fuzzy_log: list[str] | None = None, fuzzy: bool = True) -> list[str]:
    """Apply edits in place. Returns a list of error strings (empty on success).

    A SEARCH block is placed by exact match, then by whitespace-tolerant line match, then by
    edit-distance similarity (_fuzzy_find); placements by similarity are appended to fuzzy_log."""
    errors = []
    for e in edits:
        path = (repo / e.file).resolve()
        if repo.resolve() not in path.parents or not path.exists():
            errors.append(f"{e.file}: file not found in repository")
            continue
        text = read(path)
        if e.search and e.search in text:
            if text.count(e.search) > 1:
                errors.append(f"{e.file}: SEARCH block matches {text.count(e.search)} places; add more context")
                continue
            text = text.replace(e.search, e.replace, 1)
        else:
            span = _loose_find(text, e.search)
            if span is None and fuzzy:
                fz = _fuzzy_find(text, e.search)
                if fz is not None:
                    span = fz[:2]
                    if fuzzy_log is not None:
                        fuzzy_log.append(f"{e.file}: SEARCH block placed by similarity ({fz[2]:.2f}) at lines {fz[0] + 1}-{fz[1]}")
            if span is None:
                errors.append(f"{e.file}: SEARCH block not found:\n{e.search[:400]}\n{_near_miss(text, e.search)}")
                continue
            lines = text.split("\n")
            indent = re.match(r"\s*", lines[span[0]]).group(0)
            rep = e.replace.split("\n")
            # re-indent replacement relative to the first matched line
            rep_indent = re.match(r"\s*", rep[0]).group(0) if rep else ""
            rep = [indent + l[len(rep_indent):] if l.startswith(rep_indent) else l for l in rep]
            text = "\n".join(lines[:span[0]] + rep + lines[span[1]:])
        path.write_text(text, encoding="utf-8")
    return errors
