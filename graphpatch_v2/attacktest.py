"""Attack tests: a JUnit test per path-traversal (CWE-022) finding that tries the traversal for real.

The test fails while the method writes outside the directory it was given, and passes once it throws or
skips the hostile name, so it can sit in the project's test suite as a regression guard for the fix.

    python -m graphpatch_v2.attacktest <project> [--out DIR]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from javalang import tree as T

from .javasrc import parse, read
from .taint import Finding

STREAMS = {"InputStream", "ZipInputStream", "JarInputStream", "BufferedInputStream", "ByteArrayInputStream"}
ARCHIVES = {"ZipFile", "JarFile"}
PATHISH = {"File", "Path", "String"}
DIR_NAME = re.compile(r"dir|dest|target|out|root|base|folder|to$|parent|home|location", re.I)
ARCHIVE_NAME = re.compile(r"zip|jar|archive|src|source|file|in$|input|from", re.I)
PRIMS = {"boolean": "false", "char": "'x'", "float": "0f", "double": "0d", "long": "0L"}
JUNIT5 = re.compile(r"org\.junit\.jupiter|junit-jupiter")


# ------------------------------------------------------------------ source facts

def _tname(t) -> str:
    """Simple type name without generics, plus [] per dimension."""
    if t is None:
        return "void"
    name, sub = t.name, getattr(t, "sub_type", None)
    while sub is not None:  # java.io.File -> File
        name, sub = sub.name, getattr(sub, "sub_type", None)
    return name + "[]" * len(t.dimensions or [])


def _qual_tname(t) -> str:
    parts, sub = [t.name], getattr(t, "sub_type", None)
    while sub is not None:
        parts.append(sub.name)
        sub = getattr(sub, "sub_type", None)
    return ".".join(parts) + "[]" * len(t.dimensions or [])


def _find(tree, cls: str, method: str, line: int):
    """(class path, class node, method node) of the method f points at, preferring the one holding f.line."""
    best = None
    for path, node in tree.filter(T.TypeDeclaration):
        if node.name != cls:
            continue
        owners = [p.name for p in path if isinstance(p, T.TypeDeclaration)] + [node.name]
        # a nested class can be built with `new Outer.Inner()` only when it is static
        inner_ok = len(owners) == 1 or "static" in (node.modifiers or set())
        for m in node.methods:
            if m.name != method or m.position is None:
                continue
            cand = (owners, node, m, inner_ok)
            if m.position.line <= line and (best is None or m.position.line > best[2].position.line
                                            or best[2].position.line > line):
                best = cand
            elif best is None:
                best = cand
    return best


def _junit5(repo: Path) -> bool:
    for name in ("pom.xml", "build.gradle", "build.gradle.kts"):
        for p in list(Path(repo).rglob(name))[:50]:
            if "/." in "/" + p.relative_to(repo).as_posix():
                continue
            if JUNIT5.search(read(p)):
                return True
    return False


def _test_path(rel: str, pkg: str, name: str) -> str:
    prefix = rel.split("src/main/java/")[0] if "src/main/java/" in rel else ""
    return f"{prefix}src/test/java/{pkg.replace('.', '/') + '/' if pkg else ''}{name}.java"


# ------------------------------------------------------------------ code writing

class _Gen:
    def __init__(self, junit5: bool):
        self.j5 = junit5

    def assert_false(self, cond: str, msg: str) -> str:
        if self.j5:
            return f"org.junit.jupiter.api.Assertions.assertFalse({cond}, {msg});"
        return f"org.junit.Assert.assertFalse({msg}, {cond});"

    def assert_not_null(self, val: str, msg: str) -> str:
        if self.j5:
            return f"org.junit.jupiter.api.Assertions.assertNotNull({val}, {msg});"
        return f"org.junit.Assert.assertNotNull({msg}, {val});"

    @property
    def test_ann(self) -> str:
        return "@org.junit.jupiter.api.Test" if self.j5 else "@org.junit.Test"


def _default(tn: str, generic: set[str]) -> str:
    if tn in PRIMS:
        return PRIMS[tn]
    if tn in {"int", "short", "byte"}:
        return f"({tn}) 0" if tn != "int" else "0"
    if tn in generic:
        return "null"
    return f"({tn}) null"


def _pathlike(tn: str, expr_path: str) -> str:
    """Expression of type tn (File, Path or String) for a java.nio.file.Path expression."""
    return {"File": f"{expr_path}.toFile()", "Path": expr_path, "String": f"{expr_path}.toString()"}[tn]


def _zip_args(params, generic) -> tuple[list[str], bool] | None:
    """Arguments for an extractor call, and whether the zip must exist as a file on disk."""
    kinds = [_tname(p.type) for p in params]
    names = [p.name for p in params]
    archive = next((i for i, k in enumerate(kinds) if k in STREAMS | ARCHIVES | {"byte[]"}), None)
    pathish = [i for i, k in enumerate(kinds) if k in PATHISH]
    if archive is None:
        named = [i for i in pathish if ARCHIVE_NAME.search(names[i]) and not DIR_NAME.search(names[i])]
        if named:
            archive = named[0]
        elif len(pathish) >= 2:
            archive = pathish[0]
    rest = [i for i in pathish if i != archive]
    target = next((i for i in rest if DIR_NAME.search(names[i])), rest[0] if rest else None)
    if archive is None or target is None:
        return None
    on_disk = kinds[archive] in ARCHIVES | PATHISH
    args = []
    for i, k in enumerate(kinds):
        if i == archive:
            args.append({
                "InputStream": "new java.io.ByteArrayInputStream(zipBytes)",
                "ByteArrayInputStream": "new java.io.ByteArrayInputStream(zipBytes)",
                "BufferedInputStream": "new java.io.BufferedInputStream(new java.io.ByteArrayInputStream(zipBytes))",
                "ZipInputStream": "new java.util.zip.ZipInputStream(new java.io.ByteArrayInputStream(zipBytes))",
                "JarInputStream": "new java.util.jar.JarInputStream(new java.io.ByteArrayInputStream(zipBytes))",
                "byte[]": "zipBytes",
                "ZipFile": "new java.util.zip.ZipFile(archive.toFile())",
                "JarFile": "new java.util.jar.JarFile(archive.toFile())",
            }.get(k) or _pathlike(k, "archive"))
        elif i == target:
            args.append(_pathlike(k, "target"))
        else:
            args.append(_default(k, generic))
    return args, on_disk


def _path_args(params, generic, source: str) -> list[str] | None:
    kinds = [_tname(p.type) for p in params]
    idx = next((i for i, p in enumerate(params) if p.name == source), None)
    if idx is None or kinds[idx] not in PATHISH:
        return None
    args = []
    for i, (p, k) in enumerate(zip(params, kinds)):
        if i == idx:
            args.append({"String": "hostile", "File": "new java.io.File(hostile)",
                         "Path": "java.nio.file.Paths.get(hostile)"}[k])
        elif k in {"File", "Path"} or (k == "String" and DIR_NAME.search(p.name)):
            args.append(_pathlike(k, "root"))
        elif k == "String":
            args.append('"gp"')
        else:
            args.append(_default(k, generic))
    return args


def _call(gen: _Gen, owners, m, args, generic, ctor_ok: bool) -> tuple[list[str], list[str]]:
    """Statements that invoke the method, and the TODO notes they carry."""
    ref = ".".join(owners)
    static = "static" in (m.modifiers or set())
    private = "private" in (m.modifiers or set())
    todos, pre = [], []
    recv = ref
    if not static:
        if ctor_ok:
            pre.append(f"{ref} subject = new {ref}();")
        else:
            todos.append(f"construct a {ref} instance (no public no-argument constructor found)")
            pre.append(f"{ref} subject = null; // TODO: construct a {ref} the way production code does")
            pre.append(gen.assert_not_null("subject", '"TODO: construct the object under test"'))
        recv = "subject"
    if private:
        todos.append(f"{m.name} is private; called through reflection")
        types = ", ".join(("Object" if _tname(p.type) in generic else _qual_tname(p.type).split("<")[0])
                          + ("[]" if p.varargs else "") + ".class" for p in m.parameters)
        pre.append(f"java.lang.reflect.Method method = {ref}.class.getDeclaredMethod(\"{m.name}\"{', ' + types if types else ''});")
        pre.append("method.setAccessible(true);")
        call = f"method.invoke({'null' if static else 'subject'}{''.join(', ' + a for a in args)});"
    else:
        call = f"{recv}.{m.name}({', '.join(args)});"
    return pre + [call], todos


def _imports(tree) -> list[str]:
    out = []
    for imp in tree.imports or []:
        out.append(f"import {'static ' if imp.static else ''}{imp.path}{'.*' if imp.wildcard else ''};")
    return out


def attack_test(repo: Path, f: Finding) -> dict | None:
    """JUnit attack test for a CWE-022 finding, or None when it is another CWE or the method is not found."""
    if f.cwe != "CWE-022":
        return None
    path = Path(repo) / f.file
    if not path.exists():
        return None
    tree = parse(read(path))
    if tree is None:
        return None
    hit = _find(tree, f.cls, f.method, f.line)
    if hit is None:
        return None
    owners, cls_node, m, reachable = hit
    gen = _Gen(_junit5(repo))
    pkg = tree.package.name if tree.package else ""
    generic = {tp.name for tp in (m.type_parameters or [])} | {tp.name for tp in (cls_node.type_parameters or [])}
    ctors = list(getattr(cls_node, "constructors", []) or [])
    ctor_ok = (isinstance(cls_node, T.ClassDeclaration) and "abstract" not in (cls_node.modifiers or set())
               and reachable and (not ctors or any(not c.parameters and "private" not in (c.modifiers or set())
                                                   for c in ctors)))
    first = str(f.steps[0]) if f.steps else ""
    src_param = re.match(r"parameter `(\w+)`", first)
    kind, body = None, []
    if "archive entry name" in first:
        za = _zip_args(m.parameters, generic)
        if za:
            kind = "zip-slip"
            args, on_disk = za
            body = _zip_body(gen, owners, m, args, on_disk, generic, ctor_ok)
    elif src_param:
        pa = _path_args(m.parameters, generic, src_param.group(1))
        if pa is not None:
            kind = "path-param"
            body = _param_body(gen, owners, m, pa, generic, ctor_ok, src_param.group(1))
    if kind is None:
        return None
    lines, todos = body
    simple = owners[-1]
    name = f"{simple}{m.name[:1].upper()}{m.name[1:]}AttackTest"
    head = [f"package {pkg};", ""] if pkg else []
    head += _imports(tree)
    test_mod = "" if gen.j5 else "public "
    src = "\n".join(head + [
        "",
        f"/** GraphPatch attack test ({kind}) for {f.cls}.{f.method}, finding at {f.file}:{f.line} ({f.sink}).",
        " *  Fails while the method writes outside the directory it was given; passes when it throws or skips. */",
        f"{test_mod}class {name} {{",
        "",
        f"    {gen.test_ann}",
        f"    public void {m.name}RejectsPathTraversal() throws Exception {{",
        *("        " + l if l else "" for l in lines),
        "    }",
        "",
        "    private static void deleteTree(java.nio.file.Path p) {",
        "        if (p == null || !java.nio.file.Files.exists(p, java.nio.file.LinkOption.NOFOLLOW_LINKS)) {",
        "            return;",
        "        }",
        "        try (java.util.stream.Stream<java.nio.file.Path> s = java.nio.file.Files.walk(p)) {",
        "            s.sorted(java.util.Comparator.reverseOrder()).forEach(q -> q.toFile().delete());",
        "        } catch (java.io.IOException ignored) {",
        "            // best effort",
        "        }",
        "    }",
        "}",
        "",
    ])
    note = (f"{kind} test for {f.cls}.{f.method}: fails while the traversal escapes, passes once it is blocked.")
    if todos:
        note += " TODO: " + "; ".join(todos) + "."
    return {"class_name": name, "path": _test_path(f.file, pkg, name), "source": src, "kind": kind, "note": note}


def _zip_body(gen, owners, m, args, on_disk, generic, ctor_ok):
    call, todos = _call(gen, owners, m, args, generic, ctor_ok)
    lines = [
        'String escapeName = "gp_escape_" + java.util.UUID.randomUUID().toString().replace("-", "") + ".txt";',
        'java.nio.file.Path target = java.nio.file.Files.createTempDirectory("gp_target");',
        "java.nio.file.Path escape = target.getParent().resolve(escapeName);",
        "java.io.ByteArrayOutputStream buffer = new java.io.ByteArrayOutputStream();",
        "try (java.util.zip.ZipOutputStream zos = new java.util.zip.ZipOutputStream(buffer)) {",
        '    zos.putNextEntry(new java.util.zip.ZipEntry("../" + escapeName));',
        '    zos.write("graphpatch attack test".getBytes(java.nio.charset.StandardCharsets.UTF_8));',
        "    zos.closeEntry();",
        "}",
        "byte[] zipBytes = buffer.toByteArray();",
    ]
    if on_disk:
        lines += ['java.nio.file.Path archiveDir = java.nio.file.Files.createTempDirectory("gp_archive");',
                  'java.nio.file.Path archive = archiveDir.resolve("attack.zip");',
                  "java.nio.file.Files.write(archive, zipBytes);"]
    lines += ["boolean escaped;", "try {"]
    lines += ["    " + l for l in call]
    lines += [
        "} catch (Exception rejected) {",
        "    // throwing on the hostile entry is a correct fix",
        "} finally {",
        "    escaped = java.nio.file.Files.exists(escape, java.nio.file.LinkOption.NOFOLLOW_LINKS);",
        "    deleteTree(escape);",
        "    deleteTree(target);",
    ]
    if on_disk:
        lines.append("    deleteTree(archiveDir);")
    lines += ["}", gen.assert_false("escaped", '"archive entry ../" + escapeName + " was written outside the target directory: " + escape')]
    return lines, todos


def _param_body(gen, owners, m, args, generic, ctor_ok, source):
    call, todos = _call(gen, owners, m, args, generic, ctor_ok)
    lines = [
        'String escapeName = "gp_escape_" + java.util.UUID.randomUUID().toString().replace("-", "");',
        f"// `{source}` is attacker-controlled: climb two levels out of the directory the method is given",
        'String hostile = "../../" + escapeName;',
        'java.nio.file.Path base = java.nio.file.Files.createTempDirectory("gp_target");',
        'java.nio.file.Path root = java.nio.file.Files.createDirectories(base.resolve("a").resolve("b"));',
        "java.nio.file.Path escapeNearRoot = base.resolve(escapeName);",
        '// a bare relative name resolves against the working directory',
        'java.nio.file.Path escapeNearCwd = java.nio.file.Paths.get("").toAbsolutePath().resolve(hostile).normalize();',
        "boolean escaped;",
        "try {",
    ]
    lines += ["    " + l for l in call]
    lines += [
        "} catch (Exception rejected) {",
        "    // throwing on the hostile path is a correct fix",
        "} finally {",
        "    escaped = java.nio.file.Files.exists(escapeNearRoot, java.nio.file.LinkOption.NOFOLLOW_LINKS)",
        "            || java.nio.file.Files.exists(escapeNearCwd, java.nio.file.LinkOption.NOFOLLOW_LINKS);",
        "    deleteTree(escapeNearRoot);",
        "    deleteTree(escapeNearCwd);",
        "    deleteTree(base);",
        "}",
        gen.assert_false("escaped", f'"{source} = " + hostile + " created a file outside " + root'),
    ]
    return lines, todos


# ------------------------------------------------------------------ CLI

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m graphpatch_v2.attacktest", description=__doc__.split("\n\n")[0])
    ap.add_argument("project", type=Path, help="Java project root")
    ap.add_argument("--out", type=Path, help="write tests under this directory (default: the project itself)")
    a = ap.parse_args(argv)
    from .scanner import scan_repo
    out = a.out or a.project
    seen = set()
    for f in scan_repo(a.project, ["CWE-022"]):
        t = attack_test(a.project, f)
        if t is None or t["path"] in seen:
            continue
        seen.add(t["path"])
        dest = out / t["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(t["source"], encoding="utf-8")
        print(f"{dest}  [{t['kind']}] {t['note']}")
    if not seen:
        print("no CWE-022 finding to write an attack test for", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
