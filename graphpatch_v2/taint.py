"""Source-to-sink taint paths over a Java code graph.

The graph has three kinds of edges:
  * data flow inside a method (assignments, declarations, call arguments),
  * field flow inside a class (a tainted field is tainted in every method),
  * call edges between analysed methods (tainted argument -> callee parameter,
    tainted callee return -> call result).

Sources are the parameters of the methods the benchmark marks as vulnerable,
plus well-known untrusted inputs (HTTP request getters, archive entry names).
Sinks and sanitizers come from the per-CWE catalogues declared in catalogues/java.yaml. A guard such as
`if (!f.getCanonicalPath().startsWith(base)) throw ...` cleans the variables it
checks from that line on.

This is a lightweight, flow-insensitive approximation, not a sound analysis.
`calibrate` mode in run_eval.py measures how often it finds the path on the
vulnerable commit and loses it on the real fix, per CVE.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import javalang
from javalang import tree as T

from .javasrc import MethodInfo, methods_in, parse, read

# ------------------------------------------------------------------ catalogues
# Sources, sinks, sanitizers and guards are declared in catalogues/java.yaml (see catalogue.py), not here.
# Value checks such as `if (name.equals("")) throw ...` used to clear a path (paper, Threats to Validity);
# with STRICT_GUARDS they count as a guard only in a shape that really restricts the value: a negated
# allow-list check (`!ALLOWED.contains(x)`, `!"expected".equals(x)`, `!x.matches(SAFE_RE)`) or a block-list
# check whose literal names characters that matter for the weakness (`x.contains("..")`, DANGEROUS_LITERAL).

from .catalogue import load as _load_catalogue

CATALOGUE = _load_catalogue("java")
REQUEST_SOURCES = CATALOGUE["REQUEST_SOURCES"]
ENTRY_NAME_GETTERS = CATALOGUE["ENTRY_NAME_GETTERS"]
ENTRY_LIKE = CATALOGUE["ENTRY_LIKE"]
ENTRY_SOURCES = CATALOGUE["ENTRY_SOURCES"]
LOADER_SINKS = CATALOGUE["LOADER_SINKS"]
STRINGISH = CATALOGUE["STRINGISH"]
FS_CLASSES = CATALOGUE["FS_CLASSES"]
FILE_MAKERS = CATALOGUE["FILE_MAKERS"]          # constructors / types that make a path object
PATH_MAKER_CALLS = CATALOGUE["PATH_MAKER_CALLS"]
SINKS = CATALOGUE["SINKS"]
SANITIZER_PAT = CATALOGUE["SANITIZER_PAT"]
NON_PROPAGATING = CATALOGUE["NON_PROPAGATING"]  # calls whose result is never attacker-controlled data
GUARD_CALLS = CATALOGUE["GUARD_CALLS"]
WRAP_GUARD_CALLS = CATALOGUE["WRAP_GUARD_CALLS"]
WEAK_GUARD_CALLS = CATALOGUE["WEAK_GUARD_CALLS"]
DANGEROUS_LITERAL = CATALOGUE["DANGEROUS_LITERAL"]
GUARD_STMT_CALLS = CATALOGUE["GUARD_STMT_CALLS"]
STRICT_GUARDS = True     # False (run_eval --paper-mode): the guard rules exactly as described in the paper


# ------------------------------------------------------------------ results

@dataclass(frozen=True)
class Taint:
    kind: str                 # "str" or "file"
    steps: tuple              # provenance, human readable, oldest first
    roots: frozenset          # variable names this taint came through

    def extend(self, step: str, var: str | None = None, kind: str | None = None) -> "Taint":
        steps = self.steps if (self.steps and self.steps[-1] == step) else self.steps + (step,)
        if len(steps) > 14:  # keep the source and the most recent hops
            steps = steps[:1] + ("...",) + steps[-12:]
        return Taint(kind or self.kind, steps, self.roots | ({var} if var else set()))


@dataclass
class Finding:
    cwe: str
    file: str
    cls: str
    method: str
    line: int
    sink: str
    steps: tuple

    @property
    def key(self) -> str:
        return f"{self.file}::{self.cls}.{self.method}::{self.sink}"

    def render(self) -> str:
        chain = "\n".join(f"    {i + 1}. {s}" for i, s in enumerate(self.steps))
        return f"[{self.cwe}] {self.cls}.{self.method} line {self.line}: tainted data reaches `{self.sink}`\n{chain}"


@dataclass
class TargetSpec:
    """Benchmark localisation: which methods hold the vulnerability."""
    cwe: str
    files: list[str]                      # repo-relative main-source files
    methods: set[tuple]                   # (file, method name, nparams or None); "" name = whole class


# ------------------------------------------------------------------ analysis

def type_name(t) -> str:
    """Last component of a possibly qualified type: java.io.File -> File."""
    name = ""
    while t is not None:
        name = getattr(t, "name", name) or name
        t = getattr(t, "sub_type", None)
    return name


def _line(node, fallback: int) -> int:
    pos = getattr(node, "position", None)
    return pos.line if pos else fallback


class _MethodCtx:
    def __init__(self, info: MethodInfo, cls_fields: set[str]):
        self.info = info
        self.fields = cls_fields
        self.locals: dict[str, Taint] = {}
        self.local_names: set[str] = set(info.params)
        self.guarded: dict[str, int] = {}      # var -> line from which it is clean
        self.ret: Taint | None = None


class TaintAnalysis:
    def __init__(self, repo: Path, spec: TargetSpec, extra_files: list[str] | None = None):
        self.repo = Path(repo)
        self.spec = spec
        self.cwe = spec.cwe if spec.cwe in SINKS else "CWE-022"
        self.sinks = SINKS[self.cwe]
        self.sanitizer = SANITIZER_PAT[self.cwe]
        self.files = list(dict.fromkeys(spec.files + (extra_files or [])))
        self.methods: list[MethodInfo] = []
        self.class_fields: dict[str, set[str]] = {}
        self.texts: dict[str, str] = {}
        for f in self.files:
            p = self.repo / f
            if not p.exists():
                continue
            text = read(p)
            tree = parse(text)
            if tree is None:
                continue
            self.texts[f] = text
            for _, cls in tree.filter(T.TypeDeclaration):
                names = set()
                for fd in getattr(cls, "fields", []) or []:
                    names |= {d.name for d in fd.declarators}
                self.class_fields.setdefault(cls.name, set()).update(names)
            self.methods.extend(methods_in(text, f, tree))
        self.by_name: dict[tuple[str, int], list[MethodInfo]] = {}
        for m in self.methods:
            self.by_name.setdefault((m.name, m.nparams), []).append(m)
        # cross-method state
        self.param_taint: dict[int, dict[str, Taint]] = {}
        self.field_taint: dict[tuple[str, str], Taint] = {}
        self.return_taint: dict[int, Taint] = {}
        self.findings: dict[str, Finding] = {}

    # -------------------------------------------------- public

    def run(self, rounds: int = 8) -> list[Finding]:
        for m in self.methods:
            if self._is_target(m):
                self.param_taint[id(m)] = {
                    p: Taint("str", (f"parameter `{p}` of {m.cls}.{m.name} (line {m.start}) is attacker-controlled",), frozenset({p}))
                    for i, p in enumerate(m.params) if self._is_source_param(m, i)
                }
        for _ in range(rounds):
            before = self._state_size()
            for m in self.methods:
                self._analyse_method(m)
            if self._state_size() == before:
                break
        return sorted(self.findings.values(), key=lambda f: (f.file, f.line))

    # -------------------------------------------------- helpers

    def _state_size(self):
        return (sum(len(v) for v in self.param_taint.values()), len(self.field_taint),
                len(self.return_taint), len(self.findings))

    def _is_target(self, m: MethodInfo) -> bool:
        for t in self.spec.methods:
            f, name, n = (tuple(t) + (None,))[:3]
            if f == m.file and (name == "" or (name == m.name and (n is None or n == m.nparams))):
                return True
        return False

    @staticmethod
    def _is_source_param(m: MethodInfo, i: int) -> bool:
        """Non-private String-like parameters of a vulnerable method are attacker-controlled."""
        node = m.node
        mods = getattr(node, "modifiers", set()) or set()
        if "private" in mods:
            return False
        p = node.parameters[i]
        return type_name(p.type) in STRINGISH

    def _analyse_method(self, m: MethodInfo):
        ctx = _MethodCtx(m, self.class_fields.get(m.cls, set()))
        ctx.locals.update(self.param_taint.get(id(m), {}))
        body = getattr(m.node, "body", None) or []
        for _ in range(2):  # second pass picks up loop-carried flows
            ctx.guarded = {}
            for stmt in body:
                self._stmt(stmt, ctx, m.start)
        if ctx.ret is not None:
            self.return_taint.setdefault(id(m), ctx.ret)
            kind = self.sinks.get("return_kind")
            if self._is_target(m) and kind and ctx.ret.kind == kind and not isinstance(m.node, T.ConstructorDeclaration):
                self._report(m, m.end, f"return from {m.name}()", ctx.ret.extend(f"returned to callers of {m.cls}.{m.name}"))

    def _report(self, m: MethodInfo, line: int, sink: str, t: Taint):
        if m.file not in self.spec.files:
            return
        if self.cwe == "CWE-022" and t.kind != "joined":
            # traversal needs attacker data appended to a base path; resource loaders resolve
            # a bare string against their own root, so a bare tainted string counts there too
            loader = any(sink.split("(")[0].endswith(x) for x in LOADER_SINKS)
            if not (loader and t.kind == "str"):
                return
        f = Finding(self.cwe, m.file, m.cls, m.name, line, sink, t.steps + (f"SINK `{sink}` at line {line}",))
        self.findings.setdefault(f.key, f)

    # -------------------------------------------------- statements

    def _stmt(self, s, ctx: _MethodCtx, line: int):
        if s is None:
            return
        line = _line(s, line)
        if isinstance(s, (list, tuple)):
            for x in s:
                self._stmt(x, ctx, line)
            return
        if isinstance(s, T.LocalVariableDeclaration) or isinstance(s, T.VariableDeclaration):
            for d in s.declarators:
                ctx.local_names.add(d.name)
                t = self._expr(d.initializer, ctx, line) if d.initializer is not None else None
                if t is not None:
                    kind = "file" if (type_name(s.type) in FILE_MAKERS and t.kind == "str") else t.kind
                    ctx.locals[d.name] = t.extend(f"`{d.name}` = ... (line {line})", d.name, kind)
            return
        if isinstance(s, T.StatementExpression):
            e = s.expression
            if isinstance(e, T.MethodInvocation) and GUARD_STMT_CALLS.match(e.member or ""):
                refs = self._refs(e)
                if any(self._var_taint(r, ctx, line) for r in refs):
                    for r in self._with_roots(refs, ctx):
                        ctx.guarded.setdefault(r, line)
            self._expr(e, ctx, line)
            return
        if isinstance(s, T.IfStatement):
            cond_refs = self._refs(s.condition)
            is_guard = self._has_guard_call(s.condition)
            self._expr(s.condition, ctx, line)
            if is_guard and self._exits(s.then_statement):
                for r in self._with_roots(cond_refs, ctx):
                    ctx.guarded.setdefault(r, line)
                self._stmt(s.then_statement, ctx, line)
                self._stmt(s.else_statement, ctx, line)
                return
            saved = dict(ctx.guarded)
            if self._has_guard_call(s.condition, wrap=True):
                # if (isSafe(x)) { use(x) } : x is clean inside the then-branch
                for r in cond_refs:
                    ctx.guarded.setdefault(r, line)
            self._stmt(s.then_statement, ctx, line)
            ctx.guarded = dict(saved)
            self._stmt(s.else_statement, ctx, line)
            ctx.guarded = saved
            return
        if isinstance(s, T.ReturnStatement):
            if s.expression is not None:
                t = self._expr(s.expression, ctx, line)
                if t is not None and ctx.ret is None:
                    ctx.ret = t.extend(f"returned (line {line})")
            return
        if isinstance(s, T.ThrowStatement):
            return
        if isinstance(s, T.ForStatement):
            c = s.control
            if isinstance(c, T.EnhancedForControl):
                t = self._expr(c.iterable, ctx, line)
                for d in c.var.declarators:
                    ctx.local_names.add(d.name)
                    if t is not None:
                        ctx.locals[d.name] = t.extend(f"loop variable `{d.name}` (line {line})", d.name)
            elif isinstance(c, T.ForControl):
                self._stmt(c.init, ctx, line)
                self._expr(c.condition, ctx, line)
                for u in c.update or []:
                    self._expr(u, ctx, line)
            self._stmt(s.body, ctx, line)
            return
        if isinstance(s, T.TryStatement):
            for r in s.resources or []:
                ctx.local_names.add(r.name)
                t = self._expr(r.value, ctx, line)
                if t is not None:
                    ctx.locals[r.name] = t.extend(f"`{r.name}` (line {line})", r.name)
            self._stmt(s.block, ctx, line)
            for c in s.catches or []:
                self._stmt(c.block, ctx, line)
            self._stmt(s.finally_block, ctx, line)
            return
        if isinstance(s, T.SwitchStatement):
            self._expr(s.expression, ctx, line)
            for c in s.cases:
                self._stmt(c.statements, ctx, line)
            return
        if isinstance(s, T.BlockStatement):
            saved = dict(ctx.guarded)  # guards inside a block do not leak out of it
            self._stmt(s.statements, ctx, line)
            ctx.guarded = saved
            return
        if isinstance(s, (T.WhileStatement, T.DoStatement)):
            self._expr(s.condition, ctx, line)
            self._stmt(s.body, ctx, line)
            return
        if isinstance(s, T.SynchronizedStatement):
            self._stmt(s.block, ctx, line)
            return
        # anything else: scan expressions inside for sinks
        for _, child in s.filter(T.MethodInvocation):
            self._expr(child, ctx, line)
            break

    @staticmethod
    def _with_roots(refs: set[str], ctx: "_MethodCtx") -> set[str]:
        """A check on `canonical = f.getCanonicalPath()` also covers `f` and what `f` came from."""
        out = set(refs)
        for r in refs:
            t = ctx.locals.get(r)
            if t is not None:
                out |= set(t.roots)
        return out

    @staticmethod
    def _exits(stmt) -> bool:
        if stmt is None:
            return False
        if isinstance(stmt, (T.ThrowStatement, T.ReturnStatement, T.ContinueStatement, T.BreakStatement)):
            return True
        if isinstance(stmt, T.BlockStatement):
            return any(isinstance(x, (T.ThrowStatement, T.ReturnStatement, T.ContinueStatement, T.BreakStatement))
                       for x in stmt.statements or [])
        return False

    def _has_guard_call(self, cond, wrap: bool = False) -> bool:
        """True if the condition validates data. `wrap` asks for a positive check such as
        isSafe(x) or canonical.startsWith(base), not a plain contains/indexOf branch."""
        if cond is None:
            return False
        pat = WRAP_GUARD_CALLS if wrap else GUARD_CALLS
        for _, n in cond.filter(T.MethodInvocation):
            negated = "!" in (n.prefix_operators or [])
            if pat.match(n.member or "") and self._meaningful(n, negated):
                return True
            for sel in n.selectors or []:
                if isinstance(sel, T.MethodInvocation) and pat.match(sel.member or "") and self._meaningful(sel, negated):
                    return True
        return False

    def _meaningful(self, inv, negated: bool) -> bool:
        """A weak value check (equals, contains, indexOf, matches) is a guard only as an allow-list
        (negated, against something that is not an empty literal) or as a block-list whose literal
        names characters that matter for this weakness."""
        if not STRICT_GUARDS or inv.member not in WEAK_GUARD_CALLS:
            return True
        lits = [a.value.strip('"') for a in inv.arguments or [] if isinstance(a, T.Literal)]
        if any(lit == "" for lit in lits):
            return False                       # x.equals("") / x.contains("") restricts nothing
        if negated and inv.member != "indexOf":
            return True                        # allow-list: reject unless the value is a known good one
        pat = DANGEROUS_LITERAL.get(self.cwe)
        return bool(pat and any(pat.search(lit) for lit in lits))

    def _refs(self, node) -> set[str]:
        out = set()
        if node is None:
            return out
        for _, n in node.filter(T.MemberReference):
            out.add(n.member if not n.qualifier or n.qualifier == "this" else n.qualifier.split(".")[0])
        for _, n in node.filter(T.MethodInvocation):
            if n.qualifier:
                out.add(n.qualifier.split(".")[0])
        return out

    # -------------------------------------------------- expressions

    def _var_taint(self, name: str, ctx: _MethodCtx, line: int, is_field: bool = False) -> Taint | None:
        if not name:
            return None
        if not is_field and name in ctx.local_names:
            t = ctx.locals.get(name)
        else:
            t = self.field_taint.get((ctx.info.cls, name))
        if t is None:
            return None
        g = [v for v, gl in ctx.guarded.items() if gl <= line and (v == name or v in t.roots)]
        return None if g else t

    def _assign_target(self, target, t: Taint | None, ctx: _MethodCtx, line: int):
        if t is None:
            return
        if isinstance(target, T.MemberReference) and (not target.qualifier or target.qualifier == "this"):
            name = target.member
            if name in ctx.local_names and target.qualifier != "this":
                ctx.locals[name] = t.extend(f"`{name}` = ... (line {line})", name)
            elif name in ctx.fields:
                self.field_taint.setdefault((ctx.info.cls, name), t.extend(f"field `this.{name}` assigned in {ctx.info.cls}.{ctx.info.name} (line {line})", name))
        elif isinstance(target, T.This):
            sel = (target.selectors or [None])[0]
            if isinstance(sel, T.MemberReference):
                name = sel.member
                self.field_taint.setdefault((ctx.info.cls, name), t.extend(f"field `this.{name}` assigned in {ctx.info.cls}.{ctx.info.name} (line {line})", name))

    def _expr(self, e, ctx: _MethodCtx, line: int) -> Taint | None:
        if e is None:
            return None
        line = _line(e, line)
        if isinstance(e, T.Literal) or isinstance(e, T.LambdaExpression) or isinstance(e, T.MethodReference):
            return None
        if isinstance(e, T.Assignment):
            t = self._expr(e.value, ctx, line)
            if e.type == "+=" and t is None:
                t = self._expr(e.expressionl, ctx, line)
            self._assign_target(e.expressionl, t, ctx, line)
            return t
        if isinstance(e, T.MemberReference):
            if e.qualifier and e.qualifier != "this":
                t = self._var_taint(e.qualifier.split(".")[0], ctx, line)
            else:
                t = self._var_taint(e.member, ctx, line, is_field=(e.qualifier == "this"))
            return self._selectors(e, t, ctx, line)
        if isinstance(e, T.This):
            sels = list(e.selectors or [])
            t = None
            if sels and isinstance(sels[0], T.MemberReference):
                t = self._var_taint(sels[0].member, ctx, line, is_field=True)
                sels = sels[1:]
            elif sels and isinstance(sels[0], T.MethodInvocation):
                return self._call(sels[0], None, ctx, line, rest=sels[1:])
            return self._apply_selectors(sels, t, ctx, line)
        if isinstance(e, T.MethodInvocation):
            return self._call(e, e.qualifier, ctx, line, rest=list(e.selectors or []))
        if isinstance(e, T.ClassCreator):
            return self._new(e, ctx, line)
        if isinstance(e, T.BinaryOperation):
            a = self._expr(e.operandl, ctx, line)
            b = self._expr(e.operandr, ctx, line)
            if e.operator in ("+",):
                if b is not None and a is None and not isinstance(e.operandl, T.Literal):
                    return b.extend(f"appended to a path/string (line {line})", kind="joined")
                if b is not None and a is None:
                    return b.extend(f"concatenated (line {line})", kind="joined" if b.kind == "joined" else b.kind)
                return a or b
            return None  # comparisons and arithmetic yield non-string data
        if isinstance(e, T.TernaryExpression):
            self._expr(e.condition, ctx, line)
            return self._expr(e.if_true, ctx, line) or self._expr(e.if_false, ctx, line)
        if isinstance(e, T.Cast):
            return self._expr(e.expression, ctx, line)
        if isinstance(e, T.ArrayInitializer):
            ts = [self._expr(x, ctx, line) for x in e.initializers or []]
            return next((t for t in ts if t), None)
        if isinstance(e, T.ArrayCreator):
            return self._expr(e.initializer, ctx, line) if e.initializer else None
        # Unknown expression node: evaluate children for sinks, propagate any taint.
        found = None
        for attr in getattr(e, "attrs", []):
            v = getattr(e, attr, None)
            for c in (v if isinstance(v, list) else [v]):
                if isinstance(c, T.Expression) or isinstance(c, T.Primary):
                    t = self._expr(c, ctx, line)
                    found = found or t
        return found

    def _selectors(self, e, t, ctx, line):
        return self._apply_selectors(list(e.selectors or []), t, ctx, line)

    def _apply_selectors(self, sels, t, ctx, line):
        for i, s in enumerate(sels):
            if isinstance(s, T.MethodInvocation):
                return self._call(s, None, ctx, line, recv=t, rest=sels[i + 1:])
            if isinstance(s, T.ArraySelector):
                self._expr(s.index, ctx, line)
        return t

    def _new(self, e: T.ClassCreator, ctx, line) -> Taint | None:
        tname = type_name(e.type)
        args = [self._expr(a, ctx, line) for a in e.arguments or []]
        t = next((a for a in args if a), None)
        if e.body:
            pass  # anonymous classes are not analysed
        if t is not None and tname in self.sinks["ctor"]:
            self._report(ctx.info, line, f"new {tname}(...)", t.extend(f"passed to `new {tname}(...)` (line {line})"))
        if t is not None:
            kind = t.kind
            if tname in FILE_MAKERS:
                later = any(a is not None for a in args[1:])
                first_only = args and args[0] is not None and not later
                kind = "joined" if (later or t.kind == "joined") else ("file" if first_only else t.kind)
                if later:
                    t = next(a for a in args[1:] if a is not None)
            t = t.extend(f"`new {tname}(...)` built from tainted data (line {line})", kind=kind)
        return self._apply_selectors(list(e.selectors or []), t, ctx, line)

    def _call(self, e: T.MethodInvocation, qualifier: str | None, ctx: _MethodCtx, line: int,
              recv: Taint | None = None, rest=()) -> Taint | None:
        name = e.member or ""
        qual_root = qualifier.split(".")[0] if qualifier else None
        if recv is None and qual_root:
            recv = self._var_taint(qual_root, ctx, line)
        args = [self._expr(a, ctx, line) for a in e.arguments or []]
        targ = next((a for a in args if a), None)

        # ---- sources
        result: Taint | None = None
        if name in REQUEST_SOURCES:
            result = Taint("str", (f"untrusted input `{qualifier + '.' if qualifier else ''}{name}(...)` (line {line})",), frozenset())
        elif name in ENTRY_SOURCES or (name in ENTRY_NAME_GETTERS and qual_root and ENTRY_LIKE.search(qual_root)):
            result = Taint("str", (f"archive entry name `{qual_root or ''}.{name}()` (line {line})",), frozenset())

        # ---- calls into analysed methods (their bodies are checked instead of the sink catalogue)
        callees = self.by_name.get((name, len(e.arguments or [])), [])
        if not qualifier or qualifier == "this":
            callees = [c for c in callees if c.cls == ctx.info.cls or c.file == ctx.info.file]
        elif qualifier[:1].isupper():
            callees = [c for c in callees if c.cls == qualifier.split(".")[-1]]
        else:
            callees = []  # instance call on another object: type unknown, treat as library call

        # ---- sinks
        tainted_in = targ or None
        if tainted_in is not None and not callees:
            if name in self.sinks["arg"]:
                self._report(ctx.info, line, f"{qualifier + '.' if qualifier else ''}{name}(...)", tainted_in.extend(f"passed to `{name}(...)` (line {line})"))
            elif name in self.sinks["fsarg"] and (qual_root in FS_CLASSES or any(a and a.kind in ("file", "joined") for a in args)):
                tainted_in = next(a for a in args if a and (qual_root in FS_CLASSES or a.kind in ("file", "joined")))
                self._report(ctx.info, line, f"{qualifier + '.' if qualifier else ''}{name}(...)", tainted_in.extend(f"passed to `{name}(...)` (line {line})"))
        if recv is not None and not callees and name in self.sinks["recv"] and (self.cwe != "CWE-022" or recv.kind in ("file", "joined")):
            self._report(ctx.info, line, f"{qual_root or '<expr>'}.{name}()", recv.extend(f"`{name}()` called on tainted value (line {line})"))

        if callees:
            for c in callees:
                pt = self.param_taint.setdefault(id(c), {})
                for p, a in zip(c.params, args):
                    if a is not None and p not in pt:
                        pt[p] = a.extend(f"flows into `{p}` of {c.cls}.{c.name} (line {line})", p)
            rts = [self.return_taint.get(id(c)) for c in callees]
            if result is None and any(rts):
                r = next(x for x in rts if x)
                result = (targ or recv or r).extend(f"returned from {name}() (line {line})")
        elif result is None:
            # ---- unknown library call: propagate unless sanitizer / non-propagating
            if self.sanitizer.search(name) and (targ or recv):
                result = None
            elif name in NON_PROPAGATING:
                result = None
            elif targ or recv:
                src = recv or targ
                kind = src.kind
                if (qual_root in ("Paths", "Path") and name in ("get", "of")) or name in ("resolve", "resolveSibling"):
                    later = any(a is not None for a in args[1:]) if name in ("get", "of") else (targ is not None)
                    if later:
                        src, kind = next(a for a in (args[1:] if name in ("get", "of") else args) if a is not None), "joined"
                    elif kind == "str":
                        kind = "file"
                elif (len(args) >= 2 and args[0] is None and any(a is not None for a in args[1:])
                      and re.search(r"resolve|join|concat|combine|child|append|file|path", name, re.I)):
                    # helper that combines a base with attacker data, e.g. resolveFile(dir, entryName)
                    src, kind = next(a for a in args[1:] if a is not None), "joined"
                result = src.extend(f"`{name}(...)` (line {line})", kind=kind)
        return self._apply_selectors(list(rest), result, ctx, line)


# ------------------------------------------------------------------ convenience

def find_paths(repo: Path, spec: TargetSpec, extra_files: list[str] | None = None) -> list[Finding]:
    return TaintAnalysis(repo, spec, extra_files).run()


def same_package_files(repo: Path, files: list[str], limit: int = 60) -> list[str]:
    """Other Java files in the same directories, for resolving calls between classes."""
    out = []
    for f in files:
        d = (Path(repo) / f).parent
        if d.exists():
            for p in sorted(d.glob("*.java"))[:limit]:
                rel = str(p.relative_to(repo))
                if rel not in files and rel not in out:
                    out.append(rel)
    return out
