"""Taint paths in Python and JavaScript, with Tree-sitter.

The paper analyses Java with javalang (taint.py) and names a "language-parametric front end, with
Tree-sitter grammars and declarative per-language catalogues of sources, sinks and guards" as future
work. This module is that front end for two more languages. Everything language-specific is data:
the grammar comes from the tree-sitter-python / tree-sitter-javascript wheels, and the sources, sinks,
sanitizers and guards come from catalogues/python.yaml and catalogues/javascript.yaml.

The analysis is deliberately the same kind as the Java one, and simpler:
  * one unit per function (Python def / lambda; JavaScript function, arrow function, method) plus the
    module top level; nested functions are their own units;
  * taint starts at untrusted input (request fields, argv, input(), archive member names) or at a
    function parameter, and flows through assignments, destructuring, loops, string building and calls;
  * a sanitizer call (basename, shlex.quote, escape, ...) stops it; an `if <containment or allow-list
    test>: raise/return/abort` guard cleans the variables it tests from that line on;
  * a finding is a call to a sink (or, in JavaScript, an assignment to innerHTML and similar) that
    receives tainted data.
It is intraprocedural and flow-insensitive within a function: lighter than the Java analysis, which
also follows fields and calls between methods. It is not evaluated in the paper (CWE-Bench-Java is
Java only); the web workspace, the CLI tools and the NetworkX graph use it for Python and JS projects.

Findings are taint.Finding objects, so the rest of GraphPatch (risk score, graph, SARIF, web UI,
repair loop) treats them like Java findings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .catalogue import HERE, _read, _rx
from .taint import Finding

LANGUAGES = ("python", "javascript")

# node types per grammar
NODES = {
    "python": {
        "function": {"function_definition", "lambda"},
        "class": {"class_definition"},
        "call": {"call"},
        "member": {"attribute", "subscript"},
        "assign": {"assignment", "augmented_assignment", "named_expression"},
        "for": {"for_statement", "for_in_clause"},
        "if": {"if_statement"},
        "with_item": {"as_pattern"},
    },
    "javascript": {
        "function": {"function_declaration", "function_expression", "arrow_function", "method_definition",
                     "generator_function_declaration", "generator_function", "function"},
        "class": {"class_declaration", "class"},
        "call": {"call_expression", "new_expression"},
        "member": {"member_expression", "subscript_expression"},
        "assign": {"variable_declarator", "assignment_expression", "augmented_assignment_expression"},
        "for": {"for_in_statement"},
        "if": {"if_statement"},
        "with_item": set(),
    },
}
ROUTE_CALL = re.compile(r"(^|\.)(get|post|put|patch|delete|all|use|route)$")


@dataclass
class Spec:
    language: str
    extensions: tuple
    skip: tuple
    untrusted_prefix: re.Pattern
    untrusted_calls: set
    archive_name: re.Pattern
    archive_iterators: set
    sinks: dict          # cwe -> list of call names
    args: dict           # cwe -> {call name or "*": [argument index | "receiver"]}: where the dangerous value goes
    receivers: dict      # cwe -> {call name: regex}: a method call is a sink only on a matching object
    properties: dict     # cwe -> list of property names (JS assignment sinks)
    sanitizers: dict     # cwe -> regex
    guard_test: re.Pattern
    exits: set
    exit_calls: re.Pattern


@lru_cache(maxsize=None)
def spec(language: str) -> Spec:
    d = _read(HERE / f"{language}.yaml")
    s, g = d["sources"], d["guards"]
    return Spec(language, tuple(d["extensions"]), tuple(d.get("skip_paths") or ()), _rx(s["untrusted_prefix"]),
                set(s.get("untrusted_calls") or ()), _rx(s["archive_name"]), set(s.get("archive_iterators") or ()),
                {c: list(v.get("calls") or ()) for c, v in d["sinks"].items()},
                {c: dict(v.get("args") or {}) for c, v in d["sinks"].items()},
                {c: {k: _rx(r) for k, r in (v.get("receivers") or {}).items()} for c, v in d["sinks"].items()},
                {c: list(v.get("properties") or ()) for c, v in d["sinks"].items()},
                {c: _rx(v) for c, v in d["sanitizers"].items()},
                _rx(g["guard_test"]), set(g.get("exits") or ()), _rx(g["exit_calls"]))


@lru_cache(maxsize=None)
def _parser(language: str):
    import tree_sitter as ts
    if language == "python":
        import tree_sitter_python as grammar
    else:
        import tree_sitter_javascript as grammar
    return ts.Parser(ts.Language(grammar.language()))


def language_of(path: str) -> str | None:
    p = path.lower()
    for lang in LANGUAGES:
        if p.endswith(spec(lang).extensions):
            return lang
    return "java" if p.endswith(".java") else None


def source_files(repo: Path, language: str, limit: int = 1500) -> list[str]:
    sp = spec(language)
    out = []
    for p in sorted(Path(repo).rglob("*")):
        if not p.is_file() or not p.name.lower().endswith(sp.extensions):
            continue
        rel = p.relative_to(repo).as_posix()
        if any(k in f"/{rel}" for k in sp.skip):
            continue
        out.append(rel)
    return out[:limit]


def parse(text: str, language: str):
    return _parser(language).parse(text.encode("utf-8", "replace"))


def parses(text: str, language: str) -> bool:
    return not parse(text, language).root_node.has_error


# ------------------------------------------------------------------ helpers

def _t(node, src: bytes) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def _line(node) -> int:
    return node.start_point[0] + 1


def _short(text: str, n: int = 48) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _match_call(callee: str, names: list[str]) -> str | None:
    """`os.system` matches a callee ending with it; a bare `open` matches the callee's last part."""
    last = callee.rsplit(".", 1)[-1]
    for n in names:
        if ("." in n and (callee == n or callee.endswith("." + n))) or ("." not in n and last == n):
            return n
    return None


def _best(candidates):
    """Of several tainted operands, the one from real untrusted input rather than a mere parameter."""
    best = None
    for r in candidates:
        if r and (best is None or (best[0].startswith("parameter") and not r[0].startswith("parameter"))):
            best = r
    return best


@dataclass
class Unit:
    cls: str
    name: str
    start: int
    end: int
    node: object


def _unit_name(node, src: bytes, lang: str) -> str:
    name = node.child_by_field_name("name")
    if name is not None:
        return _t(name, src)
    p = node.parent
    if p is not None:
        if p.type == "variable_declarator" and p.child_by_field_name("name") is not None:
            return _t(p.child_by_field_name("name"), src)
        if p.type in ("pair",) and p.child_by_field_name("key") is not None:
            return _t(p.child_by_field_name("key"), src)
        if p.type in ("assignment_expression", "assignment") and p.child_by_field_name("left") is not None:
            return _t(p.child_by_field_name("left"), src)
        if p.type in ("arguments", "argument_list") and p.parent is not None and p.parent.type in NODES[lang]["call"]:
            callee = p.parent.child_by_field_name("function")
            ctext = _t(callee, src) if callee is not None else ""
            first = next((c for c in p.named_children), None)
            if ROUTE_CALL.search(ctext) and first is not None and first.type == "string":
                verb = ctext.rsplit(".", 1)[-1].upper()
                return f"{verb} {_t(first, src).strip(chr(34) + chr(39) + '`')}"
            return f"<callback of {_short(ctext, 24)}>"
    return f"<anonymous@{_line(node)}>"


def units(text: str, path: str, language: str | None = None) -> list[Unit]:
    """Functions of a Python or JavaScript file (and the module top level), with their line ranges."""
    lang = language or language_of(path)
    src = text.encode("utf-8", "replace")
    root = parse(text, lang).root_node
    stem = Path(path).stem
    out = [Unit(stem, "<module>", 1, root.end_point[0] + 1, root)]

    def walk(node, cls):
        for c in node.named_children:
            if c.type in NODES[lang]["class"]:
                n = c.child_by_field_name("name")
                walk(c, _t(n, src) if n is not None else cls)
            elif c.type in NODES[lang]["function"]:
                out.append(Unit(cls, _unit_name(c, src, lang), _line(c), c.end_point[0] + 1, c))
                walk(c, cls)
            else:
                walk(c, cls)
    walk(root, stem)
    return out


# ------------------------------------------------------------------ analysis

class _Analysis:
    def __init__(self, unit: Unit, src: bytes, sp: Spec, file: str, cwes: list[str]):
        self.u, self.src, self.sp, self.file, self.cwes = unit, src, sp, file, cwes
        self.N = NODES[sp.language]
        self.taint: dict[str, tuple] = {}
        self.guarded: dict[str, int] = {}      # variable -> line from which a guard cleans it
        self.findings: dict[str, Finding] = {}

    # nodes of this unit only (nested functions are their own units)
    def nodes(self):
        stack = [self.u.node]
        body = []
        while stack:
            n = stack.pop()
            body.append(n)
            for c in reversed(n.named_children):
                if c.type in self.N["function"]:
                    continue
                stack.append(c)
        return body

    def text(self, n) -> str:
        return _t(n, self.src)

    def params(self):
        ps = self.u.node.child_by_field_name("parameters")
        if ps is None and self.u.node.type == "arrow_function":
            ps = self.u.node.child_by_field_name("parameter")
        if ps is None:
            return
        line = _line(self.u.node)
        for name in self._names(ps):
            if name in ("self", "cls", "this"):
                continue
            self.taint.setdefault(name, (f"parameter `{name}` of {self.u.name} (line {line}) is attacker-controlled",))

    def _names(self, node) -> list[str]:
        """Identifiers bound by a parameter list or an assignment target (handles destructuring)."""
        if node.type in ("identifier", "shorthand_property_identifier_pattern"):
            return [self.text(node)]
        if node.type in self.N["member"]:
            return []
        out = []
        for c in node.named_children:
            if c.type in ("default_parameter", "typed_default_parameter", "assignment_pattern"):
                n = c.child_by_field_name("name") or c.child_by_field_name("left")
                if n is not None:
                    out += self._names(n)
            elif c.type == "pair_pattern":
                v = c.child_by_field_name("value")
                if v is not None:
                    out += self._names(v)
            elif c.type in ("type", "type_annotation", "string", "number"):
                continue
            else:
                out += self._names(c)
        return out

    def is_guarded(self, var: str, line: int) -> bool:
        g = self.guarded.get(var)
        return g is not None and line > g

    def eval(self, n, line: int) -> tuple | None:
        """The taint steps of an expression, or None if it is clean."""
        if n is None:
            return None
        text = self.text(n)
        if self.sp.untrusted_prefix.search(text) and n.type not in self.N["call"] | {"binary_operator", "binary_expression"}:
            return (f"untrusted input `{_short(text)}` (line {_line(n)})",)
        t = n.type
        if t in ("identifier", "shorthand_property_identifier"):
            if self.is_guarded(text, line):
                return None
            return self.taint.get(text)
        if t in self.N["call"]:
            callee_node = n.child_by_field_name("function") or n.child_by_field_name("constructor")
            callee = self.text(callee_node) if callee_node is not None else ""
            for cwe in self.cwes:
                if self.sp.sanitizers[cwe].search(callee):
                    return None
            if callee.rsplit(".", 1)[-1] in self.sp.untrusted_calls:
                return (f"untrusted input `{_short(callee)}(...)` (line {_line(n)})",)
            args = n.child_by_field_name("arguments")
            r = _best(self.eval(a.child_by_field_name("value") if a.type in ("keyword_argument", "pair") else a, line)
                      for a in (args.named_children if args is not None else []))
            if r:
                return r + (f"`{_short(callee, 32)}(...)` uses it (line {_line(n)})",)
            if callee_node is not None and callee_node.type in self.N["member"]:
                obj = callee_node.child_by_field_name("object") or callee_node.child_by_field_name("value")
                r = self.eval(obj, line)
                if r:
                    return r + (f"`.{callee.rsplit('.', 1)[-1]}(...)` on tainted data (line {_line(n)})",)
            return None
        if t in self.N["member"]:
            obj = n.child_by_field_name("object") or n.child_by_field_name("value")
            r = self.eval(obj, line)
            if r is None and self.sp.archive_name.search(text) and obj is not None and self.taint.get(self.text(obj), ("",))[0].startswith("archive entry"):
                r = self.taint[self.text(obj)]
            return r
        if t in ("lambda", "arrow_function", "function_expression", "function"):
            return None
        return _best(self.eval(c, line) for c in n.named_children)

    def assign(self, n):
        line = _line(n)
        t = n.type
        if t == "variable_declarator":
            target, value = n.child_by_field_name("name"), n.child_by_field_name("value")
        elif t in self.N["with_item"]:
            target, value = n.child_by_field_name("alias"), n.named_children[0] if n.named_children else None
        elif t == "named_expression":
            target, value = n.child_by_field_name("name"), n.child_by_field_name("value")
        else:
            target, value = n.child_by_field_name("left"), n.child_by_field_name("right")
        if target is None or value is None:
            return False
        r = self.eval(value, line)
        if not r:
            return False
        changed = False
        for name in self._names(target):
            step = f"`{name}` = ... (line {line})"
            new = r if r and r[-1] == step else r + (step,)
            if len(new) > 14:
                new = new[:1] + ("...",) + new[-12:]
            if name not in self.taint or len(self.taint[name]) > len(new) or self.taint[name][0].startswith("parameter") and not new[0].startswith("parameter"):
                self.taint[name] = new
                changed = True
        return changed

    def loop(self, n):
        target, it = n.child_by_field_name("left"), n.child_by_field_name("right")
        if target is None or it is None:
            return False
        line = _line(n)
        r = None
        if it.type in self.N["call"]:
            callee_node = it.child_by_field_name("function")
            last = self.text(callee_node).rsplit(".", 1)[-1] if callee_node is not None else ""
            if last in self.sp.archive_iterators:
                r = (f"archive entry name from `{_short(self.text(it))}` (line {line})",)
        r = r or self.eval(it, line)
        changed = False
        for name in self._names(target):
            if r and name not in self.taint:
                self.taint[name] = r + (f"`{name}` takes each item (line {line})",)
                changed = True
        return changed

    def guard(self, n):
        cond = n.child_by_field_name("condition")
        body = n.child_by_field_name("consequence")
        if cond is None or body is None or not self.sp.guard_test.search(self.text(cond)):
            return
        exits = False
        stack = [body]
        while stack:
            b = stack.pop()
            if b.type in self.sp.exits:
                exits = True
                break
            if b.type in self.N["call"]:
                f = b.child_by_field_name("function")
                if f is not None and self.sp.exit_calls.search(self.text(f)):
                    exits = True
                    break
            stack += b.named_children
        if not exits:
            return
        stack = [cond]
        while stack:
            c = stack.pop()
            if c.type == "identifier":
                self.guarded.setdefault(self.text(c), _line(n))
            stack += c.named_children

    def run(self) -> list[Finding]:
        self.params()
        body = self.nodes()
        for n in body:
            if n.type in self.N["if"]:
                self.guard(n)
        for _ in range(3):  # fixed point: assignments in any order (loops, flow-insensitive)
            changed = False
            for n in body:
                if n.type in self.N["assign"] or n.type in self.N["with_item"]:
                    changed |= self.assign(n)
                elif n.type in self.N["for"]:
                    changed |= self.loop(n)
            if not changed:
                break
        for n in body:
            if n.type in self.N["call"]:
                self.sink_call(n)
            elif n.type == "assignment_expression" and self.sp.language == "javascript":
                self.sink_property(n)
        return list(self.findings.values())

    def add(self, cwe: str, n, sink: str, r: tuple):
        line = _line(n)
        f = Finding(cwe, self.file, self.u.cls, self.u.name, line, sink, r + (f"SINK `{sink}` at line {line}",))
        self.findings.setdefault(f.key, f)

    def sink_call(self, n):
        callee_node = n.child_by_field_name("function") or n.child_by_field_name("constructor")
        if callee_node is None:
            return
        callee = self.text(callee_node)
        line = _line(n)
        for cwe in self.cwes:
            hit = _match_call(callee, self.sp.sinks.get(cwe, []))
            if not hit:
                continue
            obj = None
            if callee_node.type in self.N["member"]:
                obj = callee_node.child_by_field_name("object") or callee_node.child_by_field_name("value")
            rx = self.sp.receivers.get(cwe, {}).get(hit)
            if rx is not None and obj is not None and not rx.search(self.text(obj)):
                continue  # e.g. modal.open(...) is not fs.open(...)
            args = n.child_by_field_name("arguments")
            pos = self.sp.args.get(cwe, {})
            pos = pos.get(hit, pos.get("*"))
            if pos is None:
                r = _best(self.eval(a, line) for a in (args.named_children if args is not None else [])
                          if a.type not in ("keyword_argument", "comment"))  # shell=True, mode="w", ... are not data
                if not r and obj is not None and "." not in hit:
                    r = self.eval(obj, line)
            else:
                # only the arguments the catalogue names carry the dangerous value (the path, not file content)
                plain = [a for a in (args.named_children if args is not None else [])
                         if a.type not in ("keyword_argument", "comment", "list_splat", "dictionary_splat", "spread_element")]
                r = _best(self.eval(plain[i], line) for i in pos if isinstance(i, int) and i < len(plain))
                if not r and "receiver" in pos and obj is not None:
                    r = self.eval(obj, line)
            if r:
                self.add(cwe, n, f"{_short(callee, 40)}(...)", r)

    def sink_property(self, n):
        left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
        if left is None or left.type != "member_expression":
            return
        target = self.text(left)
        for cwe in self.cwes:
            if _match_call(target, self.sp.properties.get(cwe, [])):
                r = self.eval(right, _line(n))
                if r:
                    self.add(cwe, n, f"{_short(target, 40)} = ...", r)


def find_paths(repo: Path, files: list[str], cwes: list[str], language: str) -> list[Finding]:
    sp = spec(language)
    cwes = [c for c in cwes if c in sp.sinks]
    found: list[Finding] = []
    for rel in files:
        p = Path(repo) / rel
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        src = text.encode("utf-8", "replace")
        for u in units(text, rel, language):
            found += _Analysis(u, src, sp, rel, cwes).run()
    return found
