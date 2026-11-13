"""GraphPatch web app: a JSON API over the pipeline plus the frontend in web/.

  pip install fastapi uvicorn python-multipart
  python -m graphpatch_v2.server            # then open http://localhost:8000

Two things you can do from the page:
  * Scan & Fix: upload a zipped Java project, find source-to-sink taint paths, and let the agents patch them.
    The patch is checked by re-running the taint analysis (graph check); uploaded projects are not built.
  * Benchmark: browse the CWE-Bench-Java results written by run_eval (gp_runs/results), and start new runs.

The model key is read from the environment (GEMINI_API_KEY, or GROQ_API_KEY with GP_LLM_PROVIDER=groq); the page never asks for it.
"""

from __future__ import annotations

import difflib
import io
import json
import mimetypes
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import agents
from . import graph as taint_graph
from . import polyglot
from .javasrc import apply_edits, methods_in, numbered, parse_edits, read
from .llm import LLM, LLMError
from .rules import rule_patch
from .scanner import CWE_NAMES, MAX_FILES, risk, scan_repo
from .scanner import java_files as _java_files
from .scanner import source_files as _source_files
from .taint import SINKS, Finding, TargetSpec, find_paths

PKG = Path(__file__).resolve().parent
PROJECT = PKG.parent
ROOT = Path(os.environ.get("GP_ROOT", PROJECT / "gp_runs")).resolve()
DATASET = os.environ.get("GP_DATASET", str(PROJECT / "cwe-bench-java-master"))
UPLOADS = ROOT / "uploads"
from . import __version__
VERSION = f"{__version__} · 13 Nov 2026"
# v2.19.19: the agents can use another provider when Gemini is not available (set GP_LLM_PROVIDER before starting)
PROVIDER = os.environ.get("GP_LLM_PROVIDER", "gemini")
DEFAULT_MODELS = {"gemini": "gemini-3.8-flash", "groq": "llama-3.3-70b-versatile"}
MODEL = os.environ.get("GP_LLM_MODEL", DEFAULT_MODELS.get(PROVIDER, ""))
if PROVIDER == "groq":
    # Groq's free tier counts the reply limit against its tokens-per-minute cap; patches are short
    os.environ.setdefault("GP_LLM_MAX_TOKENS", "4096")
def _key_set() -> bool:
    from .llm import PROVIDERS
    env = PROVIDERS.get(PROVIDER, (None, None))[1]
    return bool(os.environ.get("GP_LLM_API_KEY") or (env and os.environ.get(env)) or (PROVIDER == "ollama"))


MAX_UPLOAD = 60 * 1024 * 1024
MODES = {
    "full": "GraphPatch",
    "seeded": "GraphPatch + rule seed",
    "nograph": "Multi-agent, no graph (B3)",
    "agent": "Single agent (B2)",
    "single": "Single prompt (B1)",
    "rule": "Rule-based fix, no model (B0)",
    "filectx": "Ablation: whole files",
    "nogate": "Ablation: no path gate",
    "oracle": "Developers' fix (check)",
    "noop": "No change (check)",
}

app = FastAPI(title="GraphPatch", docs_url="/api/docs")


# ================================================================== jobs

class Job:
    def __init__(self, kind: str, title: str):
        self.id = uuid.uuid4().hex[:10]
        self.kind, self.title = kind, title
        self.status = "running"            # running | done | failed
        self.events: list[dict] = []       # {t, stage, text}
        self.result: dict | None = None
        self.started = time.time()

    def log(self, stage: str, text: str):
        self.events.append({"t": round(time.time() - self.started, 1), "stage": stage, "text": text})

    def view(self, since: int = 0) -> dict:
        return {"id": self.id, "kind": self.kind, "title": self.title, "status": self.status,
                "elapsed": round(time.time() - self.started, 1), "events": self.events[since:],
                "next": len(self.events), "result": self.result if self.status != "running" else None}


JOBS: dict[str, Job] = {}
_busy = threading.Lock()  # one repair at a time: runs share worktrees and the model quota


def start_job(kind: str, title: str, fn, *args) -> Job:
    if not _busy.acquire(blocking=False):
        raise HTTPException(409, "Another repair is running. Wait for it to finish.")
    job = Job(kind, title)
    JOBS[job.id] = job

    def body():
        try:
            job.result = fn(job, *args)
            job.status = "done"
        except Exception as e:  # shown on the page, never swallowed
            job.log("error", f"{type(e).__name__}: {e}")
            job.result = {"error": str(e)}
            job.status = "failed"
        finally:
            _busy.release()

    threading.Thread(target=body, daemon=True).start()
    return job


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str, since: int = 0):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "unknown job")
    return job.view(since)


# ================================================================== status

# Optional prices for the cost column, in your currency per million tokens (input, output), e.g. from the
# Gemini price list: $env:GP_PRICE_IN="0.30"; $env:GP_PRICE_OUT="2.50"; $env:GP_PRICE_CURRENCY="$"
PRICE_IN, PRICE_OUT = os.environ.get("GP_PRICE_IN"), os.environ.get("GP_PRICE_OUT")
PRICE_CURRENCY = os.environ.get("GP_PRICE_CURRENCY", "$")


def _cost(rows: list[dict], verified: int) -> dict:
    """Totals for one approach and what one verified fix costs on average (all judged runs / verified fixes)."""
    pin = sum(r.get("prompt_tokens") or 0 for r in rows)
    pout = sum(r.get("completion_tokens") or 0 for r in rows)
    secs = sum(r.get("seconds") or 0 for r in rows)
    calls = sum(r.get("llm_calls") or 0 for r in rows)
    money = None
    try:
        if PRICE_IN and PRICE_OUT:
            money = (pin * float(PRICE_IN) + pout * float(PRICE_OUT)) / 1e6
    except ValueError:
        money = None
    per = (lambda x: round(x / verified, 4) if verified and x is not None else None)
    return {"total_tokens": pin + pout, "total_seconds": round(secs, 1), "total_calls": calls,
            "total_cost": None if money is None else round(money, 4), "currency": PRICE_CURRENCY,
            "tokens_per_fix": per(pin + pout), "seconds_per_fix": per(secs), "cost_per_fix": per(money)}


@app.get("/api/status")
def status():
    return {"version": VERSION, "model": MODEL, "key_set": _key_set(),
            "results_dir": str(ROOT / "results"), "busy": _busy.locked(), "cwes": CWE_NAMES, "modes": MODES}


# ================================================================== taint graph helpers

STEP_LINE = re.compile(r"line (\d+)")


def finding_json(f: Finding, repo: Path | None = None) -> dict:
    """A taint path as graph nodes: source, intermediate hops, sink."""
    nodes = []
    for i, s in enumerate(f.steps):
        kind = "source" if i == 0 else "sink" if s.startswith("SINK") else "step"
        m = STEP_LINE.search(s)
        nodes.append({"kind": kind, "text": s.replace("SINK ", ""), "line": int(m.group(1)) if m else None})
    out = {"key": f.key, "cwe": f.cwe, "cwe_name": CWE_NAMES.get(f.cwe, f.cwe), "file": f.file, "cls": f.cls,
           "method": f.method, "line": f.line, "sink": f.sink, "nodes": nodes, "risk": risk(f)}
    if repo is not None:
        out["snippet"] = method_snippet(repo, f)
    return out


def method_snippet(repo: Path, f: Finding) -> dict | None:
    p = repo / f.file
    if not p.exists():
        return None
    text = read(p)
    found = _units(text, f.file)
    ms = [m for m in found if m.cls == f.cls and m.name == f.method and m.start <= f.line <= m.end + 1]
    if not ms:
        ms = [m for m in found if m.cls == f.cls and m.name == f.method]
    if not ms:
        return None
    m = ms[0]
    lines = text.split("\n")
    end = min(m.end, m.start + 80)
    return {"start": m.start, "lines": lines[m.start - 1:end], "highlight": sorted(
        {n for n in (int(x) for x in STEP_LINE.findall(" ".join(f.steps))) if m.start <= n <= end})}


def _units(text: str, file: str):
    """Methods (Java) or functions (Python, JavaScript) of a file, each with .cls .name .start .end."""
    return methods_in(text, file) if file.endswith(".java") else polyglot.units(text, file)


def parse_rendered_paths(text: str) -> list[dict]:
    """Rebuild graph nodes from paths_before.txt (Finding.render output) of a benchmark run."""
    out = []
    for block in re.split(r"\n\s*\n", text.strip()):
        head = re.match(r"\[(CWE-\d+)\] (\S+?)\.(\S+) line (\d+): tainted data reaches `(.*)`", block)
        if not head:
            continue
        steps = [re.sub(r"^\s*\d+\.\s", "", l) for l in block.split("\n")[1:] if l.strip()]
        f = Finding(head[1], "", head[2], head[3], int(head[4]), head[5], tuple(steps))
        d = finding_json(f)
        d["key"] = f"{head[2]}.{head[3]}::{head[5]}"
        out.append(d)
    return out


# ================================================================== scan & fix (uploaded projects)

def _safe_extract(data: bytes, dest: Path):
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for info in z.infolist():
            target = (dest / info.filename).resolve()
            if dest.resolve() not in target.parents and target != dest.resolve():
                raise HTTPException(400, "The zip contains unsafe paths.")
        z.extractall(dest)


class ScanMeta(BaseModel):
    id: str
    name: str
    cwes: list[str]
    files: int
    findings: list[dict]
    seconds: float


def _scan_meta(scan_id: str) -> dict:
    p = UPLOADS / scan_id / "scan.json"
    if not p.exists():
        raise HTTPException(404, "unknown scan")
    return json.loads(p.read_text(encoding="utf-8"))


def _do_scan(data: bytes, name: str, cwe: str) -> dict:
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "The project is larger than 60 MB.")
    if not zipfile.is_zipfile(io.BytesIO(data)):
        raise HTTPException(400, "Please upload a .zip of a Java, Python or JavaScript project.")
    cwes = list(CWE_NAMES) if cwe == "all" else [cwe]
    if any(c not in SINKS for c in cwes):
        raise HTTPException(400, f"unknown CWE {cwe}")
    scan_id = uuid.uuid4().hex[:10]
    base = UPLOADS / scan_id
    repo = base / "original"
    repo.mkdir(parents=True)
    _safe_extract(data, repo)
    t0 = time.time()
    langs = _source_files(repo)
    findings = scan_repo(repo, cwes, langs)
    meta = {"id": scan_id, "name": name, "cwes": cwes, "languages": {k: len(v) for k, v in langs.items() if v},
            "files": sum(len(v) for v in langs.values()), "findings": [finding_json(f, repo) for f in findings],
            "seconds": round(time.time() - t0, 1)}
    (base / "scan.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta


@app.post("/api/scan")
async def scan(file: UploadFile = File(...), cwe: str = Form("all")):
    data = await file.read()
    return _do_scan(data, Path(file.filename or "project.zip").stem, cwe)


GITHUB_URL = re.compile(r"^(?:https?://)?(?:www\.)?github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/tree/([\w./-]+))?/?$")


def parse_github_url(url: str) -> tuple[str, str, str | None]:
    m = GITHUB_URL.match(url.strip())
    if not m:
        raise HTTPException(400, "Paste a GitHub link like https://github.com/owner/repo")
    return m.group(1), m.group(2), m.group(3)


def download_github(owner: str, repo: str, ref: str | None) -> bytes:
    """Download a public repository as a zip (no git needed)."""
    import urllib.error
    import urllib.request
    url = f"https://api.github.com/repos/{owner}/{repo}/zipball" + (f"/{ref}" if ref else "")
    req = urllib.request.Request(url, headers={"User-Agent": "GraphPatch", "Accept": "application/vnd.github+json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read(MAX_UPLOAD + 1)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise HTTPException(404, "Repository not found. Only public repositories work.")
        if e.code in (403, 429):
            raise HTTPException(502, "GitHub refused the download (rate limit or blocked network). Try again later or upload a .zip.")
        raise HTTPException(502, f"GitHub answered {e.code}.")
    except (urllib.error.URLError, TimeoutError) as e:
        raise HTTPException(502, f"Could not reach GitHub: {e}")
    if len(data) > MAX_UPLOAD:
        raise HTTPException(413, "The repository is larger than 60 MB.")
    return data


class GithubScan(BaseModel):
    url: str
    cwe: str = "all"


@app.post("/api/scan/github")
def scan_github(req: GithubScan):
    owner, repo, ref = parse_github_url(req.url)
    return _do_scan(download_github(owner, repo, ref), f"{owner}/{repo}", req.cwe)


class CodeScan(BaseModel):
    code: str
    cwe: str = "all"
    language: str = "auto"   # auto | java | python | javascript


def guess_language(code: str) -> str:
    if re.search(r"\b(?:class|interface|enum|record)\s+\w+[^\n]*\{", code) and re.search(r";\s*$", code, re.M) \
            and not re.search(r"^\s*(def |from \S+ import |import \S+$)", code, re.M):
        return "java"
    if re.search(r"^\s*(def |async def |from \S+ import |import \w+(\.\w+)*\s*$|@\w+(\.\w+)*\()", code, re.M) and ":" in code:
        return "python"
    if re.search(r"\b(function\b|=>|const |let |var |require\(|module\.exports|export )", code):
        return "javascript"
    return "java"


@app.post("/api/scan/code")
def scan_code(req: CodeScan):
    code = req.code.strip()
    if not code:
        raise HTTPException(400, "Paste some code first.")
    if len(code) > 500_000:
        raise HTTPException(413, "The code is too long. Upload a .zip instead.")
    lang = guess_language(code) if req.language == "auto" else req.language
    if lang not in ("java", "python", "javascript"):
        raise HTTPException(400, "language must be java, python or javascript")
    if lang == "java":
        m = re.search(r"\b(?:class|interface|enum|record)\s+(\w+)", code)
        if not m:
            raise HTTPException(400, "This does not look like a Java class.")
        pkg = re.search(r"^\s*package\s+([\w.]+)\s*;", code, re.M)
        path = "src/main/java/" + (pkg.group(1).replace(".", "/") + "/" if pkg else "") + f"{m.group(1)}.java"
        name = f"{m.group(1)}.java"
    else:
        ext = ".py" if lang == "python" else ".js"
        m = re.search(r"^\s*(?:async\s+)?(?:def|class|function)\s+(\w+)", code, re.M)
        name = (m.group(1) if m else "snippet") + ext
        path = name
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(path, code + "\n")
    return _do_scan(buf.getvalue(), name, req.cwe)


@app.get("/api/scan/{scan_id}/attack-tests.zip")
def scan_attack_tests(scan_id: str):
    """JUnit attack tests for the scan's path-traversal findings: they fail while the bug is there."""
    from .attacktest import attack_test
    meta = _scan_meta(scan_id)
    repo = UPLOADS / scan_id / "original"
    tests, seen = [], set()
    for f in scan_repo(repo, [c for c in meta["cwes"] if c == "CWE-022"]):
        if not f.file.endswith(".java"):
            continue  # JUnit attack tests exist for Java only
        t = attack_test(repo, f)
        if t and t["path"] not in seen:
            seen.add(t["path"])
            tests.append(t)
    if not tests:
        raise HTTPException(404, "No attack test could be generated: they exist for Java path traversal findings only.")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for t in tests:
            z.writestr(t["path"], t["source"])
        z.writestr("README.txt", "Copy these files into the project (same paths) and run its tests.\n"
                   "Each test tries to write outside the target folder. It FAILS while the path traversal is there\n"
                   "and PASSES once it is fixed.\n\n" + "\n".join(f"{t['path']}: {t['note']}" for t in tests))
    return FileResponseBytes(buf.getvalue(), f"attack-tests-{scan_id}.zip")


@app.get("/api/scan/{scan_id}/libraries")
def scan_libraries(scan_id: str):
    """Known vulnerabilities in the project's declared Maven/Gradle libraries, from the free OSV.dev database."""
    from .deps import OSVError, check_osv, find_dependencies
    _scan_meta(scan_id)
    deps = find_dependencies(UPLOADS / scan_id / "original")
    try:
        vulns = check_osv(deps) if deps else []
    except OSVError as e:
        raise HTTPException(502, f"{e}. The library check needs internet access to osv.dev.")
    return {"libraries": len(deps), "vulnerable": len({(v["name"], v["version"]) for v in vulns}), "vulns": vulns}


@app.get("/api/scan/{scan_id}/graphpatch.sarif")
def scan_sarif(scan_id: str):
    """The scan's findings as SARIF 2.1.0 (GitHub code scanning format)."""
    from .sarif import to_sarif
    meta = _scan_meta(scan_id)
    findings = [Finding(f["cwe"], f["file"], f["cls"], f["method"], f["line"], f["sink"],
                        tuple(n["text"] for n in f["nodes"])) for f in meta["findings"]]
    doc = to_sarif(findings, meta["cwes"])
    return FileResponseBytes(json.dumps(doc, indent=2).encode("utf-8"), f"graphpatch-{scan_id}.sarif", "application/sarif+json")


@app.get("/api/scan/{scan_id}/report.html")
def scan_report(scan_id: str):
    """A self-contained report of the scan (and the repair, if one ran) that prints cleanly to PDF."""
    meta = _scan_meta(scan_id)
    fx = UPLOADS / scan_id / "fix.json"
    fix_res = json.loads(fx.read_text(encoding="utf-8")) if fx.exists() else None
    return FileResponseBytes(render_report(meta, fix_res).encode("utf-8"), f"graphpatch-report-{scan_id}.html", "text/html")


def _ticks_to_code(text: str) -> str:
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", text)


def render_report(meta: dict, fix_res: dict | None) -> str:
    from html import escape as e
    rows = []
    for i, f in enumerate(meta["findings"], 1):
        nodes = [n for i, n in enumerate(f["nodes"]) if i == 0 or n["kind"] == "sink" or not re.match(r"^`\w+` = \.\.\.", n["text"])]
        steps = "".join(f"<li class='{n['kind']}'>{_ticks_to_code(e(n['text']))}</li>" for n in nodes)
        rows.append(f"<section><h3>{i}. {e(f['cls'])}.{e(f['method'])} <span class='tag'>{e(f['cwe_name'])} · {e(f['cwe'])}</span></h3>"
                    f"<p class='muted'>{e(f['file'])} · line {f['line']} · sink <code>{e(f['sink'])}</code></p><ol>{steps}</ol></section>")
    fix_html = ""
    if fix_res and not fix_res.get("error"):
        ok = fix_res["status"] == "closed"
        fix_html = (f"<h2>Repair</h2><p><b class='{'ok' if ok else 'bad'}'>{'Path closed' if ok else 'Not fixed'}</b> · "
                    f"paths {fix_res['paths_before']} → {fix_res['paths_after']} · tries {len(fix_res['tries'])} · "
                    f"model calls {fix_res['llm_calls']} · tokens {fix_res['tokens']:,}</p>"
                    f"<pre>{e(fix_res.get('diff') or '(no change)')}</pre>"
                    "<p class='muted'>Path closed means the taint path is gone and the code still parses. "
                    "Building and running the project's tests is still recommended.</p>")
    found = len(meta["findings"])
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>GraphPatch report · {e(meta['name'])}</title>
<style>body{{font:14px/1.55 system-ui,sans-serif;color:#111;max-width:860px;margin:40px auto;padding:0 20px}}
h1{{margin:0 0 4px}}.muted{{color:#666}}code,pre{{font-family:ui-monospace,Consolas,monospace;font-size:12.5px}}
pre{{background:#f5f5f7;padding:12px;border-radius:8px;white-space:pre-wrap}}section{{border-top:1px solid #ddd;padding:6px 0}}
.tag{{font-size:12px;font-weight:500;color:#b4233c;background:#fde8eb;padding:2px 8px;border-radius:99px}}
li.source{{color:#0e7490}}li.sink{{color:#b4233c;font-weight:600}}.ok{{color:#047857}}.bad{{color:#b4233c}}
.grid{{display:flex;gap:32px;margin:18px 0}}.grid b{{display:block;font-size:22px}}</style></head><body>
<h1>GraphPatch report</h1><p class="muted">{e(meta['name'])} · {time.strftime('%Y-%m-%d %H:%M')} · model {e(MODEL)}</p>
<div class="grid"><div>Java files<b>{meta['files']}</b></div><div>Taint paths<b class="{'bad' if found else 'ok'}">{found}</b></div>
<div>Scan time<b>{'<1' if meta['seconds'] < 1 else meta['seconds']} s</b></div></div>
<h2>Findings</h2>{''.join(rows) or '<p>No path from untrusted input to a dangerous call was found.</p>'}{fix_html}
<p class="muted" style="margin-top:32px">Found by GraphPatch's javalang taint analysis. A static scan can miss paths and can report paths that are not exploitable.</p>
</body></html>"""


@app.get("/api/scan/{scan_id}")
def get_scan(scan_id: str):
    return _scan_meta(scan_id)


@app.get("/api/sample")
def sample_project():
    """A tiny vulnerable project so the Scan & Fix page can be tried without an upload."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("demo/src/main/java/demo/ArchiveExtractor.java", SAMPLE_JAVA)
    return FileResponseBytes(buf.getvalue(), "demo-zip-slip.zip")


def FileResponseBytes(data: bytes, name: str, media_type: str = "application/zip"):
    from fastapi.responses import Response
    how = "inline" if media_type == "text/html" else "attachment"
    return Response(data, media_type=media_type, headers={"Content-Disposition": f'{how}; filename="{name}"'})


SAMPLE_JAVA = """package demo;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class ArchiveExtractor {

    public void extract(InputStream in, File targetDir) throws IOException {
        ZipInputStream zip = new ZipInputStream(in);
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            String name = entry.getName();
            File out = new File(targetDir, name);
            out.getParentFile().mkdirs();
            FileOutputStream fos = new FileOutputStream(out);
            byte[] buf = new byte[4096];
            int n;
            while ((n = zip.read(buf)) > 0) {
                fos.write(buf, 0, n);
            }
            fos.close();
        }
    }
}
"""


class FixRequest(BaseModel):
    keys: list[str] | None = None   # which findings to fix; default all
    max_iters: int = 3
    engine: str = "agents"          # agents (Planner/Coder/Critic, needs a key) | rule (rules.py, no model)


def _fix_context(repo: Path, findings: list[Finding]) -> str:
    parts = ["TAINT PATHS FOUND BY THE CODE GRAPH (untrusted source -> dangerous sink):\n"]
    parts += [f.render() + "\n" for f in findings[:8]]
    wanted: dict[str, set] = {}
    for f in findings[:8]:
        wanted.setdefault(f.file, set()).add((f.cls, f.method))
    for file, keys in wanted.items():
        text = read(repo / file)
        head = agents._header(text) if file.endswith(".java") else numbered(text, 1, min(25, text.count("\n") + 1))
        parts.append(f"\n===== {file} (imports and header) =====\n{head}\n")
        for m in _units(text, file):
            if m.name == "<module>":
                continue
            if (m.cls, m.name) in keys:
                parts.append(f"----- {m.cls}.{m.name} (lines {m.start}-{m.end}) -----\n{numbered(text, m.start, m.end)}\n")
    return "\n".join(parts)


LANG_NAME = {"java": "Java", "python": "Python", "javascript": "JavaScript (Node.js)"}
LANG_ADVICE = {
    "python": {"CWE-022": "Resolve with os.path.realpath and reject the path unless it stays inside the base directory "
                          "(os.path.commonpath); use werkzeug's secure_filename or os.path.basename for names from input or archives.",
               "CWE-078": "Do not use shell=True or os.system with input; pass an argument list to subprocess and validate against an allow-list (shlex.quote only as a last resort).",
               "CWE-079": "Escape with markupsafe.escape / html.escape, or render a template file with autoescaping instead of render_template_string on input.",
               "CWE-094": "Never eval/exec input; use ast.literal_eval, json.loads or an allow-list of operations; never unpickle untrusted data."},
    "javascript": {"CWE-022": "path.resolve the final path and reject it unless it starts with the resolved base directory plus path.sep; use path.basename for names from input.",
                   "CWE-078": "Use execFile/spawn with an argument array (no shell) and validate input against an allow-list; never concatenate input into exec().",
                   "CWE-079": "Escape HTML (e.g. escape-html) before res.send, use textContent instead of innerHTML, or sanitize with DOMPurify.",
                   "CWE-094": "Never pass input to eval, Function, vm or setTimeout strings; parse data with JSON.parse or an allow-list."},
}


def _lang(findings: list[Finding]) -> str:
    return polyglot.language_of(findings[0].file) or "java" if findings else "java"


def _brief(findings: list[Finding]) -> str:
    cwes = sorted({f.cwe for f in findings})
    lang = _lang(findings)
    adv = LANG_ADVICE.get(lang, agents.CWE_ADVICE)
    advice = "\n".join(f"- {c} ({CWE_NAMES.get(c, '')}): {adv.get(c, agents.CWE_ADVICE.get(c, ''))}" for c in cwes)
    return f"An uploaded {LANG_NAME[lang]} project contains {len(findings)} taint path(s) of type {', '.join(cwes)}.\nFix guidance:\n{advice}"


def _system(findings: list[Finding]) -> str:
    return agents.SYSTEM.replace("Java", LANG_NAME[_lang(findings)].split(" ")[0])


def _edit_rules(findings: list[Finding]) -> str:
    lang = _lang(findings)
    if lang == "java":
        return agents.EDIT_RULES
    ext = ".py" if lang == "python" else ".js"
    rules = agents.EDIT_RULES.replace("File.java", f"file{ext}").replace("new helper method", "new helper function") \
        .replace("a method shown above", "a function shown above").replace("new method", "new function")
    rules = "\n".join(l for l in rules.split("\n") if "Java source level" not in l)
    return rules + ("- Keep the indentation exactly; Python blocks depend on it.\n" if lang == "python" else "")


def _diff(orig: Path, new: Path, files: set[str]) -> str:
    out = []
    for f in sorted(files):
        a = read(orig / f).split("\n") if (orig / f).exists() else []
        b = read(new / f).split("\n") if (new / f).exists() else []
        out += difflib.unified_diff(a, b, f"a/{f}", f"b/{f}", lineterm="")
    return "\n".join(out)


def _run_fix(job: Job, scan_id: str, req: FixRequest) -> dict:
    meta = _scan_meta(scan_id)
    base = UPLOADS / scan_id
    orig = base / "original"
    targets = scan_repo(orig, meta["cwes"])
    if req.keys:
        targets = [f for f in targets if f.key in set(req.keys)]
    if not targets:
        raise ValueError("no taint paths to fix")
    if req.engine == "rule":
        return _run_rule_fix(job, scan_id, meta, orig, targets)
    total = len(targets)
    if not req.keys:
        # one focused patch works far better than one patch for every kind of bug: take the top finding's type
        lang0 = polyglot.language_of(targets[0].file)
        targets = [f for f in targets if f.cwe == targets[0].cwe and polyglot.language_of(f.file) == lang0][:4]
    llm = LLM(PROVIDER, MODEL)
    # the web app should fail in minutes, not retry for an hour like the batch runs
    llm.timeout, llm.max_attempts = 300, 3
    llm.on_retry = lambda msg: job.log("check", msg)
    llm.retry_empty = True
    name = CWE_NAMES.get(targets[0].cwe, targets[0].cwe)
    job.log("graph", f"{len(targets)} {name} path(s) selected for repair" + (f" (of {total} found)" if total > len(targets) else ""))
    ctx = _fix_context(orig, targets)
    brief = _brief(targets)
    system, edit_rules = _system(targets), _edit_rules(targets)
    job.log("planner", "Planner is reading the paths and the code...")
    plan = llm.chat(system, f"{brief}\n\nCODE CONTEXT:\n{ctx}\n\nWrite a short remediation plan (at most 8 bullet "
                    "points): where untrusted data enters, which call is dangerous, which lines to change, the check to "
                    "add, and what behaviour must stay the same. Do not write code.", role="planner")
    job.log("planner", plan)
    critique, prev, tries = "", "", []
    work = base / "patched"
    for it in range(1, req.max_iters + 1):
        if work.exists():
            shutil.rmtree(work)
        shutil.copytree(orig, work)
        retry = f"\nYOUR PREVIOUS PATCH (reverted):\n{prev[:6000] or '(nothing applied)'}\n\nWHY IT WAS REJECTED:\n{critique}\n" if critique else ""
        job.log("coder", f"Coder is writing patch {it}...")
        try:
            reply = llm.chat(system, f"{brief}\n\nPLAN:\n{plan}\n\nCODE CONTEXT (line numbers are for reference only):\n"
                             f"{ctx}\n{retry}\n{edit_rules}", role="coder")
        except LLMError as e:
            if not tries:
                raise
            # keep what the earlier tries produced instead of losing the whole repair
            job.log("check", f"The model did not answer for patch {it} ({e}). Showing the result of patch {it - 1}.")
            break
        edits = parse_edits(reply)
        errors = apply_edits(work, edits) if edits else ["The reply contained no edit blocks."]
        touched = {e.file for e in edits}
        diff = _diff(orig, work, touched)
        if errors:
            verdict = {"status": "rejected", "stage": "apply", "remaining": None,
                       "feedback": f"{len(errors)} edit block(s) could not be applied.\n\n" + "\n\n".join(errors)}
        else:
            job.log("check", "Re-running the taint analysis on the patched code...")
            after = {f.key: f for f in scan_repo(work, meta["cwes"])}
            left = [f for f in targets if f.key in after]
            parse_ok = all(_parses(work / f) for f in touched)
            if not parse_ok:
                verdict = {"status": "rejected", "stage": "syntax", "remaining": len(left),
                           "feedback": "The patched file no longer parses."}
            elif left:
                verdict = {"status": "rejected", "stage": "graph", "remaining": len(left),
                           "feedback": "Untrusted data still reaches a sink:\n\n" + "\n\n".join(after[f.key].render() for f in left)}
            else:
                verdict = {"status": "closed", "stage": "graph", "remaining": 0,
                           "feedback": "Every selected taint path is gone and the code still parses."}
        tries.append({"try": it, "diff": diff, **verdict})
        job.log("check", f"Try {it}: {verdict['status']} ({verdict['stage']})")
        if verdict["status"] == "closed" or it == req.max_iters:
            break
        prev = diff
        job.log("critic", "Critic is explaining what went wrong...")
        try:
            critique = llm.chat(system, f"{brief}\n\nPATCH:\n{diff[:8000] or '(not applied)'}\n\nVALIDATOR OUTPUT:\n"
                            f"{verdict['feedback'][:6000]}\n\n{agents.CRITIC_FORMAT}", role="critic", json_mode=True)
        except LLMError as e:
            job.log("check", f"The Critic got no answer ({e}). Showing the result of patch {it}.")
            break
        crit, _why = agents.parse_critique(critique)
        if crit is not None:
            critique = agents.render_critique(crit)
        job.log("critic", critique)
    final = tries[-1]
    result = {"scan": scan_id, "status": final["status"], "engine": "agents", "tries": tries, "plan": plan, "diff": final["diff"],
            "paths_before": len(targets), "paths_after": final["remaining"],
            "tokens": llm.usage.prompt_tokens + llm.usage.completion_tokens, "llm_calls": llm.usage.calls}
    (UPLOADS / scan_id / "fix.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _run_rule_fix(job: Job, scan_id: str, meta: dict, orig: Path, targets: list[Finding]) -> dict:
    """The no-model repair: the standard path check from rules.py, checked by the same taint re-scan."""
    targets = [f for f in targets if f.cwe == "CWE-022" and f.file.endswith(".java")]
    if not targets:
        raise ValueError("the rule fix only handles Java path traversal (CWE-22); use Repair with agents for the others")
    job.log("graph", f"{len(targets)} path traversal path(s) selected for the rule fix")
    work = UPLOADS / scan_id / "patched"
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(orig, work)
    reply = rule_patch(work, "CWE-022", targets)
    edits = parse_edits(reply)
    job.log("coder", f"The rule adds a containment check (normalise the path, keep it inside its base folder) "
                     f"in {len(edits)} place(s). No model is used.")
    errors = apply_edits(work, edits) if edits else ["The rule found no place to add a check."]
    touched = {e.file for e in edits}
    diff = _diff(orig, work, touched)
    if errors:
        verdict = {"status": "rejected", "stage": "apply", "remaining": None, "feedback": "\n\n".join(errors)}
    else:
        job.log("check", "Re-running the taint analysis on the patched code...")
        after = {f.key: f for f in scan_repo(work, meta["cwes"])}
        left = [f for f in targets if f.key in after]
        if not all(_parses(work / f) for f in touched):
            verdict = {"status": "rejected", "stage": "syntax", "remaining": len(left),
                       "feedback": "The patched file no longer parses."}
        elif left:
            verdict = {"status": "rejected", "stage": "graph", "remaining": len(left),
                       "feedback": "The rule could not close every path:\n\n" + "\n\n".join(after[f.key].render() for f in left)}
        else:
            verdict = {"status": "closed", "stage": "graph", "remaining": 0,
                       "feedback": "Every selected taint path is gone and the code still parses."}
    job.log("check", f"Rule fix: {verdict['status']} ({verdict['stage']})")
    result = {"scan": scan_id, "status": verdict["status"], "engine": "rule", "tries": [{"try": 1, "diff": diff, **verdict}],
              "plan": "Rule-based fix (no model): add the standard containment check after each tainted path is built.",
              "diff": diff, "paths_before": len(targets), "paths_after": verdict["remaining"], "tokens": 0, "llm_calls": 0}
    (UPLOADS / scan_id / "fix.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _parses(p: Path) -> bool:
    if not p.exists():
        return True
    lang = polyglot.language_of(p.name)
    if lang in polyglot.LANGUAGES:
        return polyglot.parses(read(p), lang)
    from .javasrc import parse
    return parse(read(p)) is not None


@app.post("/api/scan/{scan_id}/fix")
def fix(scan_id: str, req: FixRequest):
    _scan_meta(scan_id)
    if req.engine not in ("agents", "rule"):
        raise HTTPException(400, "unknown repair engine")
    try:
        if req.engine == "agents":
            LLM(PROVIDER, MODEL)  # fail fast if the key is missing
    except LLMError as e:
        raise HTTPException(400, str(e))
    job = start_job("fix", f"Fix {scan_id}", _run_fix, scan_id, req)
    return job.view()


@app.get("/api/scan/{scan_id}/patched.zip")
def download_patched(scan_id: str):
    work = UPLOADS / scan_id / "patched"
    if not work.exists():
        raise HTTPException(404, "no patched project yet")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in work.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(work).as_posix())
    return FileResponseBytes(buf.getvalue(), f"patched-{scan_id}.zip")


# ================================================================== benchmark (CWE-Bench-Java results)

def load_runs() -> list[dict]:
    jl = ROOT / "results" / "runs.jsonl"
    if not jl.exists():
        return []
    latest = {}
    for line in jl.read_text(encoding="utf-8").splitlines():
        if line.strip():
            r = json.loads(line)
            # only the paper model's runs (and model-free checks such as oracle); older test runs with other models stay out
            if (r.get("model") or "") not in ("", MODEL):
                continue
            latest[(r.get("mode"), r.get("slug"))] = r
    return list(latest.values())


def paper_cves() -> list[str]:
    f = PKG / "paper_cves.txt"
    return [l.split("#")[0].strip() for l in f.read_text().splitlines() if l.split("#")[0].strip()] if f.exists() else []


@app.get("/api/benchmark")
def benchmark():
    runs = load_runs()
    by_cve: dict[str, dict] = {}
    for c in paper_cves():
        by_cve[c] = {"cve": c, "cwe": None, "slug": None, "runs": {}}
    for r in runs:
        e = by_cve.setdefault(r["cve"], {"cve": r["cve"], "cwe": None, "slug": None, "runs": {}})
        e["cwe"], e["slug"] = r.get("cwe"), r["slug"]
        e["runs"][r["mode"]] = {k: r.get(k) for k in ("status", "stage", "iterations", "paths_before", "paths_after",
                                                         "seconds", "model", "pov_ok", "graph_eval_ok")}
        e["runs"][r["mode"]]["tokens"] = (r.get("prompt_tokens") or 0) + (r.get("completion_tokens") or 0)
    summary = []
    for mode in MODES:
        rs = [r for r in runs if r["mode"] == mode]
        if not rs:
            continue
        st = Counter(r["status"] for r in rs)
        valid = [r for r in rs if r["status"] not in ("excluded", "error")]
        toks = sorted((r.get("prompt_tokens") or 0) + (r.get("completion_tokens") or 0) for r in valid)
        secs = sorted(r.get("seconds") or 0 for r in valid)
        summary.append({"mode": mode, "name": MODES[mode], "total": len(rs), "judged": len(valid),
                        "verified": st["verified"], "plausible": st["plausible"], "rejected": st["rejected"],
                        "error": st["error"], "excluded": st["excluded"],
                        "still_vulnerable": sum(1 for r in valid if r["status"] == "plausible"
                                                and (r.get("graph_eval_ok") is False or r.get("pov_ok") is False)),
                        "median_tokens": toks[len(toks) // 2] if toks else 0,
                        "median_seconds": secs[len(secs) // 2] if secs else 0,
                        **_cost(valid, st["verified"])})
    return {"cves": sorted(by_cve.values(), key=lambda e: e["cve"]), "summary": summary,
            "models": sorted({r.get("model") for r in runs if r.get("model")})}


@app.get("/api/benchmark/{mode}/{slug}")
def benchmark_detail(mode: str, slug: str):
    if mode not in MODES or not re.fullmatch(r"[\w.\-]+", slug):
        raise HTTPException(400, "bad request")
    art = ROOT / "results" / "artifacts" / mode / slug
    row = next((r for r in load_runs() if r["mode"] == mode and r["slug"] == slug), None)
    if not art.exists() and not row:
        raise HTTPException(404, "no result for this CVE and mode")

    def txt(name):
        p = art / name
        return p.read_text(encoding="utf-8", errors="replace") if p.exists() else None

    tries = []
    for p in sorted(art.glob("verdict_*.json"), key=lambda p: (not p.stem[8:].isdigit(), p.stem)):
        n = p.stem[8:]
        if n.isdigit():
            v = json.loads(p.read_text(encoding="utf-8"))
            tries.append({"try": int(n), "status": v.get("status"), "stage": v.get("stage"),
                          "feedback": (v.get("feedback") or "")[:5000], "diff": txt(f"patch_{n}.diff")})
    transcript = json.loads(txt("transcript.json") or "[]")
    return {"row": row, "paths": parse_rendered_paths(txt("paths_before.txt") or ""), "plan": txt("plan.md"),
            "final_diff": txt("final.diff"), "tries": tries,
            "conversation": [{"role": m["role"], "reply": m["reply"][:8000]} for m in transcript]}


class RunRequest(BaseModel):
    cve: str
    mode: str = "full"


def _run_benchmark(job: Job, req: RunRequest) -> dict:
    cmd = [sys.executable, "-u", "-m", "graphpatch_v2.run_eval", "--root", str(ROOT), "--dataset", DATASET,
           "run", "--mode", req.mode, "--cves", req.cve, "--docker", "always"]
    if req.mode not in ("rule", "oracle", "noop"):
        cmd += ["--provider", PROVIDER, "--model", MODEL]
    job.log("run", " ".join(cmd[3:]))
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    with subprocess.Popen(cmd, cwd=PROJECT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                          encoding="utf-8", errors="replace", env=env) as p:
        for line in p.stdout:
            if line.strip() and not line.lstrip().startswith("|"):  # skip the summary table run_eval prints
                job.log("run", line.rstrip())
    if p.returncode != 0:
        raise RuntimeError(f"run_eval exited with code {p.returncode}")
    row = next((r for r in load_runs() if r["mode"] == req.mode and r["cve"] == req.cve), None)
    return {"row": row}


@app.post("/api/benchmark/run")
def benchmark_run(req: RunRequest):
    if req.mode not in MODES or not re.fullmatch(r"CVE-\d{4}-\d+", req.cve):
        raise HTTPException(400, "bad request")
    job = start_job("benchmark", f"{req.cve} · {req.mode}", _run_benchmark, req)
    return job.view()


# ================================================================== frontend

WEB = PKG / "web"
# Windows can map .js to text/plain in the registry, which browsers refuse for module scripts
mimetypes.add_type("application/javascript", ".js")
mimetypes.add_type("text/css", ".css")
app.mount("/assets", StaticFiles(directory=WEB), name="assets")

# The React frontend (../frontend, built with `npm run build`) is served at / when it has been built;
# the original single-page UI stays available at /classic.
REACT = PROJECT / "frontend" / "dist"
if (REACT / "static").is_dir():
    app.mount("/static", StaticFiles(directory=REACT / "static"), name="react-static")


@app.get("/classic")
def classic():
    return FileResponse(WEB / "index.html")


# ================================================================== extra API for the React frontend

@app.get("/api/scans")
def list_scans():
    """Every scan in this workspace, newest first, with its finding counts and the state of its repair."""
    out = []
    for p in sorted(UPLOADS.glob("*/scan.json"), key=lambda p: p.stat().st_mtime, reverse=True) if UPLOADS.exists() else []:
        try:
            m = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        fx = p.parent / "fix.json"
        fix = None
        if fx.exists():
            try:
                f = json.loads(fx.read_text(encoding="utf-8"))
                fix = {"status": f.get("status"), "engine": f.get("engine"), "tries": len(f.get("tries") or []),
                       "paths_before": f.get("paths_before"), "paths_after": f.get("paths_after")}
            except (OSError, json.JSONDecodeError):
                pass
        fs = m.get("findings") or []
        by_cwe = Counter(f.get("cwe") for f in fs)
        levels = Counter((f.get("risk") or {}).get("level") or "low" for f in fs)
        top = sorted(fs, key=lambda f: -(f.get("risk") or {}).get("score", 0))[:3]
        out.append({"id": m["id"], "name": m.get("name"), "files": m.get("files"), "cwes": m.get("cwes"),
                    "languages": m.get("languages") or {"java": m.get("files") or 0},
                    "findings": len(m.get("findings") or []), "by_cwe": dict(by_cwe),
                    "max_risk": max((f.get("risk", {}).get("score", 0) for f in m.get("findings") or []), default=None),
                    "levels": {k: levels.get(k, 0) for k in ("critical", "high", "medium", "low")},
                    "top": [{k: f.get(k) for k in ("key", "cwe", "cwe_name", "file", "cls", "method", "line", "sink")}
                            | {"score": (f.get("risk") or {}).get("score"), "level": (f.get("risk") or {}).get("level")} for f in top],
                    "created": round(p.stat().st_mtime), "fix": fix})
    return {"scans": out}


def _findings_of(meta: dict) -> list[Finding]:
    """Rebuild taint.Finding objects from a saved scan (its nodes are the path steps)."""
    out = []
    for f in meta.get("findings") or []:
        steps = tuple(("SINK " if n["kind"] == "sink" else "") + n["text"] for n in f["nodes"])
        out.append(Finding(f["cwe"], f["file"], f["cls"], f["method"], f["line"], f["sink"], steps))
    return out


@app.get("/api/scan/{scan_id}/graph")
def scan_graph(scan_id: str):
    """The program-wide taint graph of a scan, built and analysed with NetworkX (graph.py)."""
    meta = _scan_meta(scan_id)
    G = taint_graph.build(_findings_of(meta))
    out = {"summary": taint_graph.summary(G), "hot_files": taint_graph.hot_files(G),
           "choke_points": taint_graph.choke_points(G), "graph": taint_graph.to_json(G), "after": None}
    patched = UPLOADS / scan_id / "patched"
    if (UPLOADS / scan_id / "fix.json").exists() and patched.exists():
        out["after"] = taint_graph.summary(taint_graph.build(scan_repo(patched, meta["cwes"])))
    return out


@app.get("/api/scan/{scan_id}/taint-graph.graphml")
def scan_graphml(scan_id: str):
    G = taint_graph.build(_findings_of(_scan_meta(scan_id)))
    buf = io.BytesIO()
    import networkx as nx
    nx.write_graphml(G, buf)
    return FileResponseBytes(buf.getvalue(), f"taint-graph-{scan_id}.graphml", "application/graphml+xml")


@app.get("/api/scan/{scan_id}/fix")
def get_fix(scan_id: str):
    """The saved result of the last repair of this scan (diffs, tries, verdicts)."""
    _scan_meta(scan_id)
    fx = UPLOADS / scan_id / "fix.json"
    if not fx.exists():
        raise HTTPException(404, "no repair has run for this scan")
    return json.loads(fx.read_text(encoding="utf-8"))


@app.get("/api/scan/{scan_id}/source")
def get_source(scan_id: str, path: str, version: str = "original"):
    """One source file of the scanned project, as uploaded or as patched, for the side-by-side diff."""
    _scan_meta(scan_id)
    if version not in ("original", "patched"):
        raise HTTPException(400, "version must be original or patched")
    base = (UPLOADS / scan_id / version).resolve()
    f = (base / path).resolve()
    if base not in f.parents or not f.is_file():
        raise HTTPException(404, "file not found")
    return {"path": path, "version": version, "text": f.read_text(encoding="utf-8", errors="replace")}


@app.get("/")
def index():
    if (REACT / "index.html").exists():
        return FileResponse(REACT / "index.html")
    return FileResponse(WEB / "index.html")


@app.get("/{page:path}")
def spa(page: str):
    """Client-side routes of the React frontend (/scanner, /taint-graph, ...)."""
    if page.startswith(("api/", "static/", "assets/")) or not (REACT / "index.html").exists():
        raise HTTPException(404, "not found")
    return FileResponse(REACT / "index.html")


def main():
    import argparse
    import webbrowser

    import uvicorn

    ap = argparse.ArgumentParser(prog="graphpatch_v2.server")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    a = ap.parse_args()
    if not a.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(f"http://localhost:{a.port}")).start()
    print(f"GraphPatch {VERSION} is running at http://localhost:{a.port}  (Ctrl+C to stop)")
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")


if __name__ == "__main__":
    main()
