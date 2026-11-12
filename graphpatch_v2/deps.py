"""Vulnerable-library check for Java projects (Maven and Gradle) against the free OSV.dev database.

Usage: python -m graphpatch_v2.deps <project folder> [--json out.json]
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path

import requests

MAX_POMS = 200
MAX_DETAILS = 200
BATCH = 500
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
SKIP_DIRS = {"target", "build", "node_modules"}
GRADLE_FILES = ("build.gradle", "build.gradle.kts")
GRADLE_CONFIGS = ("implementation", "api", "compile", "runtime", "compileOnly", "runtimeOnly", "testImplementation",
                  "testCompile", "testRuntime", "testRuntimeOnly", "testCompileOnly", "annotationProcessor", "kapt",
                  "providedCompile", "providedRuntime", "compileClasspath", "runtimeClasspath")
GRADLE_RE = re.compile(r"\b(?:%s)\s*\(?\s*['\"]([\w.\-]+):([\w.\-]+):([^'\"@:\s]+)(?::[^'\"@]*)?(?:@\w+)?['\"]"
                       % "|".join(GRADLE_CONFIGS))
PROP_RE = re.compile(r"\$\{([^}]+)\}")


class OSVError(Exception):
    """The OSV.dev API could not be reached or gave an unusable answer."""


@dataclass
class Dep:
    name: str
    version: str
    file: str
    ecosystem: str = "Maven"


@dataclass
class _Pom:
    path: Path
    group: str
    artifact: str
    version: str
    parent_version: str
    props: dict[str, str]
    managed: dict[str, str]
    deps: list[tuple[str, str, str]]
    parent: _Pom | None = None


def _walk(repo: Path, names: tuple[str, ...]) -> list[Path]:
    out = []
    for root, dirs, files in os.walk(repo):
        dirs[:] = sorted(d for d in dirs if not d.startswith(".") and d not in SKIP_DIRS)
        out += [Path(root) / f for f in sorted(files) if f in names]
    return out


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(el: ET.Element | None, name: str) -> ET.Element | None:
    if el is None:
        return None
    return next((c for c in el if isinstance(c.tag, str) and _local(c.tag) == name), None)


def _text(el: ET.Element | None, name: str) -> str:
    c = _child(el, name)
    return (c.text or "").strip() if c is not None else ""


def _dep_list(el: ET.Element | None) -> list[tuple[str, str, str]]:
    deps = _child(el, "dependencies")
    if deps is None:
        return []
    return [(_text(d, "groupId"), _text(d, "artifactId"), _text(d, "version"))
            for d in deps if isinstance(d.tag, str) and _local(d.tag) == "dependency"]


def _read_pom(path: Path) -> _Pom | None:
    try:
        root = ET.parse(path).getroot()
    except (ET.ParseError, OSError):
        return None
    parent = _child(root, "parent")
    props_el = _child(root, "properties")
    props = {_local(p.tag): (p.text or "").strip() for p in (props_el if props_el is not None else [])
             if isinstance(p.tag, str)}
    managed = {f"{g}:{a}": v for g, a, v in _dep_list(_child(root, "dependencyManagement")) if v}
    return _Pom(path, _text(root, "groupId") or _text(parent, "groupId"), _text(root, "artifactId"),
                _text(root, "version") or _text(parent, "version"), _text(parent, "version"),
                props, managed, _dep_list(root))


def _link_parent(pom: _Pom, poms: dict[Path, _Pom]) -> None:
    root = ET.parse(pom.path).getroot()
    parent = _child(root, "parent")
    if parent is None:
        return
    rel = _child(parent, "relativePath")
    rel_text = (rel.text or "").strip() if rel is not None else "../pom.xml"
    if not rel_text:
        return
    target = (pom.path.parent / rel_text).resolve()
    if target.is_dir():
        target = target / "pom.xml"
    pom.parent = poms.get(target)


def _chain(pom: _Pom) -> list[_Pom]:
    """The pom and its in-repo ancestors, nearest first."""
    out, seen = [], set()
    while pom is not None and pom.path not in seen and len(out) < 20:
        seen.add(pom.path)
        out.append(pom)
        pom = pom.parent
    return out


def _context(pom: _Pom) -> tuple[dict[str, str], dict[str, str]]:
    props: dict[str, str] = {}
    managed: dict[str, str] = {}
    for p in reversed(_chain(pom)):
        props.update(p.props)
        managed.update(p.managed)
    props.update({"project.version": pom.version, "version": pom.version, "pom.version": pom.version,
                  "project.groupId": pom.group, "pom.groupId": pom.group, "project.artifactId": pom.artifact,
                  "project.parent.version": pom.parent_version, "parent.version": pom.parent_version})
    return props, managed


def _resolve(value: str, props: dict[str, str]) -> str:
    for _ in range(10):
        if "${" not in value:
            break
        new = PROP_RE.sub(lambda m: props.get(m.group(1), m.group(0)), value)
        if new == value:
            break
        value = new
    return value


def _usable(version: str) -> bool:
    return bool(version) and "${" not in version and not version.startswith(("[", "(")) and "," not in version


def find_dependencies(repo: Path) -> list[Dep]:
    """Declared Maven coordinates with concrete versions from every pom.xml and build.gradle(.kts) in the repo."""
    repo = Path(repo).resolve()
    poms = {}
    for path in _walk(repo, ("pom.xml",))[:MAX_POMS]:
        pom = _read_pom(path)
        if pom:
            poms[path.resolve()] = pom
    for pom in poms.values():
        _link_parent(pom, poms)
    out: list[Dep] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, version: str, path: Path) -> None:
        if _usable(version) and (name, version) not in seen:
            seen.add((name, version))
            out.append(Dep(name, version, path.relative_to(repo).as_posix()))

    for pom in poms.values():
        props, managed = _context(pom)
        for g, a, v in pom.deps:
            g, a = _resolve(g, props), _resolve(a, props)
            if not g or not a or "${" in g + a:
                continue
            name = f"{g}:{a}"
            add(name, _resolve(v or managed.get(name, ""), props), pom.path)
    for path in _walk(repo, GRADLE_FILES):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in GRADLE_RE.finditer(text):
            version = m.group(3)
            if "$" not in version and "+" not in version:
                add(f"{m.group(1)}:{m.group(2)}", version, path)
    return out


def _request(method, url: str, timeout: float, **kw) -> dict:
    try:
        r = method(url, timeout=timeout, **kw)
        r.raise_for_status()
        return r.json()
    except requests.HTTPError as e:
        raise OSVError(f"osv.dev answered {e.response.status_code if e.response is not None else '?'} for {url}") from None
    except requests.RequestException as e:
        raise OSVError(f"could not reach osv.dev: {type(e).__name__}: {str(e)[:200]}") from None
    except ValueError:
        raise OSVError(f"osv.dev gave a non-JSON answer for {url}") from None


def _severity(vuln: dict) -> str:
    parts = [s.get("score", "") for s in vuln.get("severity") or [] if s.get("score")]
    level = (vuln.get("database_specific") or {}).get("severity")
    if level:
        parts.insert(0, str(level))
    return " ".join(parts)


def _fixed(vuln: dict, name: str) -> list[str]:
    out: list[str] = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != "Maven" or pkg.get("name") != name:
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed") and ev["fixed"] not in out:
                    out.append(ev["fixed"])
    return out


def check_osv(deps: list[Dep], timeout: float = 20) -> list[dict]:
    """Known vulnerabilities for the given dependencies, one dict per (dependency, vulnerability)."""
    hits: list[tuple[Dep, str]] = []
    for i in range(0, len(deps), BATCH):
        chunk = deps[i:i + BATCH]
        body = {"queries": [{"package": {"ecosystem": d.ecosystem, "name": d.name}, "version": d.version}
                            for d in chunk]}
        results = _request(requests.post, OSV_BATCH_URL, timeout, json=body).get("results") or []
        for dep, res in zip(chunk, results):
            hits += [(dep, v["id"]) for v in (res or {}).get("vulns") or [] if v.get("id")]
    details: dict[str, dict] = {}
    out = []
    for dep, vid in hits:
        if vid not in details and len(details) < MAX_DETAILS:
            details[vid] = _request(requests.get, OSV_VULN_URL.format(vid), timeout)
        vuln = details.get(vid, {})
        out.append({"name": dep.name, "version": dep.version, "file": dep.file, "id": vid,
                    "aliases": [a for a in vuln.get("aliases") or [] if a.startswith("CVE-")],
                    "summary": vuln.get("summary") or (vuln.get("details") or "")[:200],
                    "severity": _severity(vuln), "fixed": _fixed(vuln, dep.name),
                    "url": f"https://osv.dev/vulnerability/{vid}"})
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m graphpatch_v2.deps", description=__doc__.split("\n\n")[0])
    ap.add_argument("project", type=Path, help="folder of the Java project")
    ap.add_argument("--json", type=Path, help="also write the findings to this JSON file")
    a = ap.parse_args(argv)
    deps = find_dependencies(a.project)
    try:
        vulns = check_osv(deps)
    except OSVError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    for v in vulns:
        cves = ",".join(v["aliases"]) or "-"
        sev = v["severity"].split(" ")[0] if v["severity"] else "-"
        fixed = ",".join(v["fixed"]) or "-"
        print(f"{v['name']}:{v['version']:<12} {v['id']:<20} {cves:<28} {sev:<9} fixed: {fixed}  ({v['file']})")
    print(f"{len(deps)} dependencies checked, {len(vulns)} known vulnerabilities "
          f"in {len({(v['name'], v['version']) for v in vulns})} of them")
    if a.json:
        a.json.write_text(json.dumps({"dependencies": [asdict(d) for d in deps], "vulnerabilities": vulns},
                                     indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
