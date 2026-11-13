// GraphPatch frontend: plain ES modules, no build step.

const $ = (sel, el = document) => el.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const view = $("#view");

async function api(path, opts = {}) {
  const r = await fetch(path, opts);
  const body = r.headers.get("content-type")?.includes("json") ? await r.json() : await r.text();
  if (!r.ok) throw new Error(body?.detail || body || r.statusText);
  return body;
}

let STATUS = { modes: {}, cwes: {} };
const MAIN_MODES = ["full", "nograph", "single", "rule"];
const RISK_CLS = { critical: "bad", high: "bad", medium: "warn", low: "gray" };
const riskPill = (r) => (r ? `<span class="pill ${RISK_CLS[r.level] || "gray"}" title="${esc(r.why.join("\n"))}">Risk ${r.score}</span>` : "");
const STATUS_STYLE = {
  verified: ["ok", "Verified"], closed: ["ok", "Path closed"], plausible: ["warn", "Plausible"],
  rejected: ["bad", "Rejected"], error: ["gray", "Error"], excluded: ["gray", "Excluded"],
};
const pill = (s) => {
  const [cls, label] = STATUS_STYLE[s] || ["gray", s || "–"];
  return `<span class="pill ${cls}"><span class="dot"></span>${esc(label)}</span>`;
};
const modeName = (m) => STATUS.modes?.[m] || m;
const fmtSec = (s) => (s == null ? "–" : s < 1 ? "<1 s" : s < 90 ? `${Math.round(s)} s` : `${(s / 60).toFixed(1)} min`);
const fmtNum = (n) => (n == null ? "–" : Number(n).toLocaleString("en"));

// ------------------------------------------------------------------ shared renderers

function pathGraph(f, closed = false) {
  // hide bookkeeping hops like "`name` = ..." so the path reads as a short story
  const nodes = f.nodes.filter((n, i) => i === 0 || n.kind === "sink" || !/^`\w+` = \.\.\./.test(n.text));
  let i = 0;
  const html = nodes.map((n) => {
    const tag = n.kind === "source" ? "Untrusted input" : n.kind === "sink" ? (closed ? "Guarded" : "Dangerous call") : "Flows into";
    const text = esc(n.text.replace(/\s*\(line \d+\)/, "").replace(/ at line \d+$/, "")).replace(/`([^`]+)`/g, "<code>$1</code>");
    return `<div class="pnode ${n.kind}" style="--i:${i++ * 2}"><div class="tag">${tag}${n.line ? `<span class="ln">L${n.line}</span>` : ""}</div>${text}</div>`;
  });
  return `<div class="path-graph ${closed ? "closed" : ""}">${html.map((h, k) => (k ? `<div class="pedge" style="--i:${k * 2 - 1}"></div>` : "") + h).join("")}</div>`;
}

function codeView(snippet) {
  if (!snippet) return `<div class="empty small">Source not available.</div>`;
  const hl = new Set(snippet.highlight || []);
  const rows = snippet.lines.map((l, i) => {
    const n = snippet.start + i;
    return `<tr class="${hl.has(n) ? "hl" : ""}"><td class="n">${n}</td><td>${esc(l) || " "}</td></tr>`;
  });
  return `<div class="code"><table>${rows.join("")}</table></div>`;
}

function diffView(diff) {
  if (!diff || !diff.trim()) return `<div class="empty small">No changes.</div>`;
  const rows = diff.split("\n").map((l) => {
    const cls = l.startsWith("+++") || l.startsWith("---") || l.startsWith("diff ") || l.startsWith("index ") ? "file"
      : l.startsWith("@@") ? "hunk" : l.startsWith("+") ? "add" : l.startsWith("-") ? "del" : "";
    return `<tr class="${cls}"><td>${esc(l) || " "}</td></tr>`;
  });
  return `<div class="code"><table>${rows.join("")}</table></div>`;
}

// ------------------------------------------------------------------ Overview

// Hero: the attack path as a short, readable story. Untrusted input flows down to a file write,
// then GraphPatch inserts a check and the path is closed. Loops while the page is open.
function attackStory() {
  const row = (k, tag, code, say) => `<div class="srow ${k}" data-k="${k}">
      <div class="snode"><span class="stag">${tag}</span><code>${code}</code></div>
      <p class="say">${say}</p></div>`;
  const pipe = (k) => `<div class="spipe" data-p="${k}"><span></span></div>`;
  return `<div class="story frame" id="story">
    <div class="story-head"><span class="mono small"><span class="faint">Example ·</span> Zip Slip in ArchiveExtractor.java</span><span class="st" id="story-st">reading the code…</span></div>
    <div class="story-body">
      ${row("src", "① untrusted input", "entry.getName()", "A file name from an uploaded zip. <b>The attacker chooses it</b>, e.g. <code>../../evil.sh</code>")}
      ${pipe(1)}
      ${row("mid", "② flows into", "new File(targetDir, name)", "The name is joined to the target folder <b>without any check</b>.")}
      ${pipe(2)}
      <div class="sguard-wrap">${row("guard", "+ GraphPatch adds", "if (!isInside(dir, file)) throw", "The agents insert a check on the path.")}${pipe(3)}</div>
      ${row("snk", "③ dangerous call", "new FileOutputStream(file)", `<span class="bad-t">Writes the file <b>outside</b> the folder. Attack works.</span><span class="ok-t">Never reached with a bad name. <b>Path closed.</b></span>`)}
    </div>
    <div class="story-steps">${["Find path", "Plan", "Patch", "Re-check"].map((t, i) => `<span data-s="${i}"><i></i>${t}</span>`).join("")}</div>
  </div>`;
}

function runStory() {
  const root = $("#story");
  if (!root) return;
  const st = $("#story-st", root), on = (sel, c, v = true) => root.querySelectorAll(sel).forEach((e) => e.classList.toggle(c, v));
  const status = (t, c = "") => { st.textContent = t; st.className = `st ${c}`; };
  const step = (i) => root.querySelectorAll(".story-steps span").forEach((e) => { e.classList.toggle("on", +e.dataset.s === i); e.classList.toggle("done", +e.dataset.s < i); });
  const T = [
    [0, () => { root.className = "story frame"; on(".srow", "lit", false); on(".spipe", "flow", false); step(-1); status("reading the code…"); }],
    [600, () => { step(0); on(".srow.src", "lit"); status("tracing untrusted input…"); }],
    [1700, () => { on('[data-p="1"]', "flow"); on(".srow.mid", "lit"); }],
    [2800, () => { on('[data-p="2"]', "flow"); on(".srow.snk", "lit"); root.classList.add("attack"); status("1 attack path found", "bad"); }],
    [5000, () => { step(1); status("planner reads only this path…"); }],
    [6200, () => { step(2); root.classList.add("guarded"); on(".srow.guard", "lit"); status("coder inserts a check…"); }],
    [7800, () => { step(3); status("re-checking the graph…"); }],
    [8900, () => { root.classList.remove("attack"); root.classList.add("safe"); step(4); status("0 paths · closed", "ok"); }],
  ];
  const cycle = () => {
    if (!root.isConnected) return;
    T.forEach(([t, f]) => setTimeout(() => root.isConnected && f(), t));
    setTimeout(cycle, 13500);
  };
  cycle();
}

// count numbers up from 0 when they scroll into view
function countUp(el) {
  const m = el.textContent.match(/^(\d+)(.*)$/);
  if (!m) return;
  const end = +m[1], rest = m[2], t0 = performance.now(), dur = 1100;
  const tick = (t) => {
    const p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 3);
    el.textContent = Math.round(end * e) + rest;
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

const GLYPHS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789<>/{}=_";
function scramble(el) {
  const final = el.textContent, t0 = performance.now(), dur = 700;
  const tick = (t) => {
    const p = Math.min(1, (t - t0) / dur), keep = Math.floor(final.length * p);
    el.textContent = final.slice(0, keep) + [...final.slice(keep)].map((c) => (c === " " ? " " : GLYPHS[(Math.random() * GLYPHS.length) | 0])).join("");
    if (p < 1) requestAnimationFrame(tick); else el.textContent = final;
  };
  requestAnimationFrame(tick);
}

function animateIn(scope = view) {
  const io = new IntersectionObserver((es) => es.forEach((e) => {
    if (!e.isIntersecting) return;
    e.target.classList.add("in");
    e.target.querySelectorAll("[data-count]").forEach(countUp);
    e.target.querySelectorAll("[data-scramble]").forEach(scramble);
    io.unobserve(e.target);
  }), { threshold: 0.15 });
  scope.querySelectorAll(".reveal").forEach((el) => io.observe(el));
}

const ICONS = {
  graph: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="5" cy="6" r="2.5"/><circle cx="19" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M7 7.5l3.5 8.5M17 7.5l-3.5 8.5M7.5 6h9"/></svg>',
  plan: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M9 5h10M9 12h10M9 19h10"/><path d="M4 5l1 1 2-2M4 12l1 1 2-2M4 19l1 1 2-2"/></svg>',
  patch: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M8 7l-5 5 5 5M16 7l5 5-5 5M14 4l-4 16"/></svg>',
  shield: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.4 8.2-8 9-4.6-.8-8-4.5-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg>',
  github: '<svg viewBox="0 0 24 24" fill="currentColor"><path d="M12 2a10 10 0 00-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.9 1.52 2.34 1.08 2.91.83.09-.65.35-1.09.63-1.34-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.02a9.5 9.5 0 015 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.38.2 2.4.1 2.65.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v2.75c0 .27.18.58.69.48A10 10 0 0012 2z"/></svg>',
  upload: '<svg width="30" height="30" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4m0 0l-4 4m4-4l4 4"/><path d="M4 16v2a2 2 0 002 2h12a2 2 0 002-2v-2"/></svg>',
};

async function overview() {
  return homePipeline();
}

// ------------------------------------------------------------------ Scan & Fix

let SCAN = null;      // current scan result
let SEL = 0;          // selected finding index
let FIX = null;       // finished fix result

// where the user is in Scan & Fix: 0 choose a project, 1 see the paths, 2 fix, 3 fixed
const scanStep = () => (!SCAN ? 0 : FIX ? 3 : 1);
const stepBar = (n) => `<ol class="stepbar">${["Choose a project", "See the attack paths", "Fix the code", "Check the result"]
  .map((t, i) => `<li class="${i < n ? "done" : i === n ? "on" : ""}"><span>${i < n ? "✓" : i + 1}</span>${t}</li>`).join("")}</ol>`;

async function scanPage() {
  view.innerHTML = `<div class="page-title fade-in"><h2>Scan &amp; Fix</h2><p>Upload a Java project. Find the paths. Repair them.</p></div><div id="steps"></div><div id="scan-body"></div>`;
  SCAN ? renderScan() : renderUpload();
}
const showStep = (n = scanStep()) => { if ($("#steps")) $("#steps").innerHTML = stepBar(n); };

let SRC = "zip";
const SOURCES = [["zip", "Upload .zip"], ["github", "GitHub link"], ["code", "Paste code"]];

function renderUpload(error = "") {
  showStep(0);
  const cwes = Object.entries(STATUS.cwes || {});
  const panes = {
    zip: `<label class="drop" id="drop">
      <input type="file" id="file" accept=".zip" hidden>
      <div class="ic">${ICONS.upload}</div>
      <h3>Drop a project .zip</h3>
      <p class="muted small" style="margin-top:6px">or click to browse · max 60 MB</p>
    </label>`,
    github: `<form class="card pad src-pane" id="gh-form">
      <div class="ic-sm">${ICONS.github}</div>
      <h3>Scan a GitHub repository</h3>
      <p class="muted small">Public repositories only. A branch link (…/tree/main) also works.</p>
      <div class="row" style="gap:10px;margin-top:18px;flex-wrap:nowrap">
        <input id="gh-url" class="inp" style="flex:1" placeholder="https://github.com/owner/repo" autocomplete="off" spellcheck="false">
        <button class="btn primary" type="submit">Scan</button>
      </div>
    </form>`,
    code: `<form class="card pad src-pane" id="code-form">
      <textarea id="code" class="inp mono" spellcheck="false" placeholder="Paste Java, Python or JavaScript code here…"></textarea>
      <div class="row" style="margin-top:12px"><span class="faint small">One file, with its imports. The language is detected automatically.</span><span class="spacer"></span><button class="btn primary" type="submit">Scan</button></div>
    </form>`,
  };
  $("#scan-body").innerHTML = `
  <div class="tabs src-tabs fade-in">${SOURCES.map(([k, v]) => `<button class="tab ${k === SRC ? "on" : ""}" data-src="${k}">${v}</button>`).join("")}</div>
  <div class="split fade-in" style="grid-template-columns: 1fr 320px">
    <div>${panes[SRC]}</div>
    <div class="card pad stack">
      <div><div class="faint small" style="margin-bottom:8px">Vulnerability type</div>
        <select id="cwe"><option value="all">All types</option>${cwes.map(([k, v]) => `<option value="${k}">${esc(v)} (${k})</option>`).join("")}</select></div>
      <div style="border-top:1px solid var(--border);padding-top:18px">
        <div class="faint small" style="margin-bottom:8px">No project at hand?</div>
        <button class="btn" id="sample" style="width:100%;justify-content:center">Try the Zip Slip example</button>
      </div>
    </div>
  </div>
  ${error ? `<div class="notice bad" style="margin-top:16px">${esc(error)}</div>` : ""}`;
  document.querySelectorAll("[data-src]").forEach((el) => (el.onclick = () => { SRC = el.dataset.src; renderUpload(); }));
  if (SRC === "zip") {
    const drop = $("#drop"), file = $("#file");
    drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
    drop.addEventListener("dragleave", () => drop.classList.remove("over"));
    drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); if (e.dataTransfer.files[0]) doScan(e.dataTransfer.files[0]); });
    file.addEventListener("change", () => file.files[0] && doScan(file.files[0]));
  } else if (SRC === "github") {
    $("#gh-form").onsubmit = (e) => {
      e.preventDefault();
      const url = $("#gh-url").value.trim();
      if (url) runScan(url.replace(/^https?:\/\/(www\.)?github\.com\//, ""), "/api/scan/github", { url, cwe: $("#cwe").value });
    };
  } else {
    $("#code-form").onsubmit = (e) => {
      e.preventDefault();
      const code = $("#code").value;
      if (code.trim()) runScan("your code", "/api/scan/code", { code, cwe: $("#cwe").value });
    };
  }
  $("#sample").onclick = async () => {
    const blob = await (await fetch("/api/sample")).blob();
    doScan(new File([blob], "zip-slip-example.zip"));
  };
}

async function runScan(label, url, body) {
  const cwe = $("#cwe")?.value || "all";
  $("#scan-body").innerHTML = `<div class="card pad row"><span class="spinner"></span> ${url.endsWith("github") ? "Downloading and tracing" : "Tracing taint paths in"} <b>${esc(label)}</b>…</div>`;
  try {
    SCAN = await api(url, body instanceof FormData ? { method: "POST", body } : { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...body, cwe }) });
    SEL = 0; FIX = null;
    renderScan();
  } catch (e) { renderUpload(e.message); }
}

function doScan(f) {
  const fd = new FormData();
  fd.append("file", f);
  fd.append("cwe", $("#cwe")?.value || "all");
  runScan(f.name, "/api/scan", fd);
}

function renderScan() {
  const s = SCAN, fs = s.findings;
  showStep();
  const stat = (k, v) => `<div><div class="faint small">${k}</div><div style="font-size:20px;font-weight:700">${v}</div></div>`;
  $("#scan-body").innerHTML = `
  <div class="card scan-head fade-in">
    <div class="row scan-stats">
      ${stat("Project", esc(s.name))}${stat("Source files", s.files)}${stat("Attack paths", `<span style="color:${fs.length ? "var(--sink)" : "var(--ok)"}">${fs.length}</span>`)}${stat("Scan time", fmtSec(s.seconds))}
      <span class="spacer"></span><button class="btn sm" id="new-scan">New scan</button>
    </div>
    <div class="scan-actions">
      ${fs.length ? `<div class="act-group"><div class="act-label">Fix</div><div class="row">
        ${fs.some((f) => f.cwe === "CWE-022") ? `<button class="btn" id="rule-fix" title="The standard path check, written by a fixed rule. No model and no API key; path traversal only.">Rule fix <span class="faint small">no key</span></button>` : ""}
        <button class="btn primary" id="fix" ${STATUS.key_set ? "" : 'data-nokey="1"'}>Repair with agents${STATUS.key_set ? "" : ' <span class="small">· needs key</span>'}</button></div></div>` : ""}
      <div class="act-group"><div class="act-label">Export</div><div class="row">
        <a class="btn" href="/api/scan/${s.id}/report.html" target="_blank" rel="noopener">Report</a>
        <a class="btn" href="/api/scan/${s.id}/graphpatch.sarif" title="Findings in SARIF 2.1.0, the format GitHub code scanning reads">SARIF</a>
        <button class="btn" id="libs" title="Look up the project's Maven/Gradle libraries in the free OSV.dev vulnerability database (needs internet)">Check libraries</button></div></div>
    </div>
  </div>
  ${fs.length ? `
  <div class="split fade-in">
    <div class="card" style="overflow:hidden">
      ${fs.map((f, i) => `<div class="list-item ${i === SEL ? "sel" : ""}" data-i="${i}">
        <div class="row"><span class="t">${esc(f.cls)}.${esc(f.method)}</span><span class="spacer"></span>${riskPill(f.risk)}<span class="pill bad">${esc(f.cwe_name)}</span></div>
        <div class="s">→ ${esc(f.sink)} · L${f.line}</div></div>`).join("")}
    </div>
    <div class="grid g2" id="detail" style="align-items:start"></div>
  </div>` : `<div class="card empty"><h3>No vulnerable paths found</h3><p>Nothing flows from untrusted input to a dangerous call.</p></div>`}
  ${fs.length && !STATUS.key_set ? `<div class="notice info" style="margin-top:16px">Repair with agents needs a Gemini key: click it to see how to add one.${fs.some((f) => f.cwe === "CWE-022") ? " <b>Rule fix</b> works without a key for path traversal." : ""}</div>` : ""}
  <div id="libs-area"></div>
  <div id="fix-area" class="section"></div>`;
  $("#libs").onclick = checkLibraries;
  $("#new-scan").onclick = () => { SCAN = null; renderUpload(); };
  document.querySelectorAll(".list-item").forEach((el) => (el.onclick = () => { SEL = +el.dataset.i; renderScan(); }));
  if ($("#fix")) $("#fix").onclick = () => ($("#fix").dataset.nokey ? $("#keyhelp")?.click() : startFix("agents"));
  if ($("#rule-fix")) $("#rule-fix").onclick = () => startFix("rule");
  if (fs.length) renderDetail();
  if (FIX) renderFixResult(FIX);
}

async function checkLibraries() {
  const area = $("#libs-area");
  $("#libs").disabled = true;
  area.innerHTML = `<div class="card pad row section"><span class="spinner"></span> Looking up libraries in OSV.dev…</div>`;
  let d;
  try { d = await api(`/api/scan/${SCAN.id}/libraries`); }
  catch (e) { area.innerHTML = `<div class="notice bad section">${esc(e.message)}</div>`; $("#libs").disabled = false; return; }
  const head = `${d.libraries} declared ${d.libraries === 1 ? "library" : "libraries"} checked · ${d.vulnerable} with known vulnerabilities`;
  area.innerHTML = `<div class="card section fade-in" style="overflow:auto"><div class="card-head"><h3>Libraries</h3><span class="faint small">${head}</span>
    <span class="spacer"></span><span class="faint small">source: OSV.dev · declared dependencies only</span></div>
    ${d.vulns.length ? `<table class="data"><thead><tr><th>Library</th><th>Version</th><th>Advisory</th><th>Severity</th><th>Fixed in</th><th>Summary</th></tr></thead><tbody>
      ${d.vulns.map((v) => `<tr><td class="mono small">${esc(v.name)}</td><td class="mono small">${esc(v.version)}</td>
        <td><a href="${esc(v.url)}" target="_blank" rel="noopener">${esc(v.aliases?.[0] || v.id)}</a></td>
        <td class="small">${esc((v.severity || "").split(" ")[0] || "–")}</td><td class="mono small">${esc((v.fixed || []).join(", ") || "–")}</td>
        <td class="small">${esc(v.summary || "")}</td></tr>`).join("")}</tbody></table>`
      : `<div class="empty small">${d.libraries ? "No known vulnerabilities in the declared libraries." : "No pom.xml or build.gradle with library versions was found in this project."}</div>`}</div>`;
}

function renderDetail() {
  const f = SCAN.findings[SEL];
  const closed = FIX?.status === "closed";
  $("#detail").innerHTML = `
  <div class="card pad"><div class="row" style="margin-bottom:16px"><h3>Taint path</h3><span class="spacer"></span><span class="faint small mono">${esc(f.file.split("/").pop())}</span></div>${pathGraph(f, closed)}
    ${f.risk ? `<div class="risk-box"><div class="row">${riskPill(f.risk)}<span class="faint small">${esc(f.risk.level)} risk · a triage score, not a probability</span></div><ul class="faint small">${f.risk.why.map((w) => `<li>${esc(w)}</li>`).join("")}</ul></div>` : ""}</div>
  <div class="card pad"><div class="row" style="margin-bottom:16px"><h3>Code</h3></div>${codeView(f.snippet)}</div>`;
}

const AGENTS = [["planner", "Planner"], ["coder", "Coder"], ["check", "Validator"], ["critic", "Critic"]];

async function startFix(engine = "agents") {
  const area = $("#fix-area");
  area.innerHTML = `<div class="card frame fade-in"><div class="card-head"><span class="spinner"></span><h3>${engine === "rule" ? "Rule fix at work" : "Agents at work"}</h3><span class="spacer"></span>
    <div class="agents-bar">${AGENTS.map(([k, n]) => `<span class="agent" data-a="${k}">${n}</span>`).join("")}</div><span class="faint small mono" id="elapsed" style="min-width:48px;text-align:right"></span></div>
    <div class="pad"><div class="timeline" id="tl"></div></div></div>`;
  area.scrollIntoView({ behavior: "smooth" });
  const btns = ["#fix", "#rule-fix"].map((b) => $(b)).filter(Boolean);
  showStep(2);
  const was = btns.map((b) => b.disabled);
  btns.forEach((b) => (b.disabled = true));
  let job;
  try { job = await api(`/api/scan/${SCAN.id}/fix`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ engine }) }); }
  catch (e) { area.innerHTML = `<div class="notice bad">${esc(e.message)}</div>`; btns.forEach((b, i) => (b.disabled = was[i])); return; }
  const result = await followJob(job.id, $("#tl"), $("#elapsed"));
  if (result?.status === "failed") { area.insertAdjacentHTML("beforeend", `<div class="notice bad" style="margin-top:12px">${friendlyError(result.result?.error)}</div>`); btns.forEach((b, i) => (b.disabled = was[i])); return; }
  FIX = result.result;
  renderScan();
}

// turn the provider's raw error into something a person can act on
function friendlyError(msg = "") {
  if (/denied access|PERMISSION_DENIED/.test(msg)) return `<b>Google has blocked this Gemini account</b>, so the agents cannot run live. Only Google can lift it (appeal in the Google Cloud console). Meanwhile use <b>Rule fix</b>, or open <b>Benchmark</b>, click a GraphPatch result and press <b>Replay</b> to watch a saved agent run.`;
  if (/HTTP 401|API key not valid|valid API key/i.test(msg)) return `<b>The API key was not accepted.</b> Check that you copied the whole key, then restart the app with it.`;
  if (/HTTP 429|quota/i.test(msg)) return `<b>The model's quota is used up for now.</b> Wait a little and try again, or use <b>Rule fix</b>.`;
  return esc(msg);
}

const WHO = { graph: "Code graph", planner: "Planner", coder: "Coder", check: "Validator", critic: "Critic", run: "Pipeline", error: "Error" };

async function followJob(id, tl, elapsedEl) {
  let next = 0;
  for (;;) {
    const j = await api(`/api/jobs/${id}?since=${next}`);
    next = j.next;
    for (const e of j.events) {
      tl.insertAdjacentHTML("beforeend", `<div class="tl ${e.stage} fade-in"><div class="who">${WHO[e.stage] || e.stage} · ${e.t}s</div><div class="what">${md(e.text)}</div></div>`);
      tl.lastElementChild.scrollIntoView({ block: "nearest" });
      document.querySelectorAll(".agent").forEach((a) => {
        if (a.dataset.a === e.stage) a.classList.add("on");
        else if (a.classList.contains("on")) { a.classList.remove("on"); a.classList.add("done"); }
      });
    }
    if (elapsedEl) elapsedEl.textContent = fmtSec(j.elapsed);
    if (j.status !== "running") return j;
    await new Promise((r) => setTimeout(r, 1200));
  }
}

function renderFixResult(r) {
  const ok = r.status === "closed";
  const stat = (k, v) => `<div class="metric" style="padding:0"><div class="label">${k}</div><div class="value" style="font-size:30px">${v}</div></div>`;
  $("#fix-area").innerHTML = `
  <div class="card ${ok ? "frame" : ""} fade-in">
    <div class="card-head">${pill(r.status)}<h3>${ok ? "Vulnerability fixed" : "Not fixed yet"}</h3>
      <span class="info" title="Accepted when re-running the taint analysis finds no path and the code still parses. Uploaded projects are not compiled; benchmark CVEs are.">i</span>
      <span class="spacer"></span>${SCAN.findings.some((f) => f.cwe === "CWE-022") ? `<a class="btn sm" href="/api/scan/${SCAN.id}/attack-tests.zip" title="JUnit tests that try a path traversal attack: they fail on the original code and pass on the fixed code">Download attack tests</a>` : ""}${ok ? `<a class="btn sm primary" href="/api/scan/${SCAN.id}/patched.zip">Download fixed project</a>` : ""}</div>
    <div class="grid g4 pad">
      ${stat("Paths", `${r.paths_before} → <span style="color:${ok ? "var(--ok)" : "var(--sink)"}">${r.paths_after ?? "–"}</span>`)}${stat("Tries", r.tries.length)}${stat("Model calls", r.llm_calls)}${stat("Tokens", fmtNum(r.tokens))}
    </div>
    <div class="pad" style="padding-top:0">${diffView(r.diff)}</div>
    <div class="pad" style="padding-top:0">
      ${r.tries.map((t) => `<details class="try"><summary>Try ${t.try} ${pill(t.status)}</summary><div><pre class="fb">${esc(t.feedback)}</pre>${diffView(t.diff)}</div></details>`).join("")}
      <details class="try"><summary>Plan</summary><div><pre class="fb">${esc(r.plan)}</pre></div></details>
    </div>
  </div>`;
}

// ------------------------------------------------------------------ Benchmark

let BENCH = null;

async function benchmarkPage() {
  view.innerHTML = `<div class="card pad row"><span class="spinner"></span> Loading…</div>`;
  BENCH = await api("/api/benchmark");
  const have = BENCH.summary.map((s) => s.mode);
  const modes = MAIN_MODES.filter((m) => have.includes(m)).concat(have.filter((m) => !MAIN_MODES.includes(m)));
  view.innerHTML = `
  <div class="section-head page-title fade-in" style="margin-bottom:22px">
    <div><h2>Benchmark</h2><p>${BENCH.cves.length} real CVEs · ${esc(BENCH.models.join(", ") || "model pending")}</p></div>
    <div class="legend">${["verified", "plausible", "rejected", "error"].map((s) => `<span><i style="background:${COLORS[s]}"></i>${STATUS_STYLE[s][1]}</span>`).join("")}</div>
  </div>
  <div class="row bench-tools fade-in"><div class="chips" id="chips">${[["all", `All ${BENCH.cves.length}`], ["judged", `Judged ${BENCH.cves.filter((c) => !isExcl(c)).length}`], ["excluded", `Excluded ${BENCH.cves.filter(isExcl).length}`]]
    .map(([k, t]) => `<button class="chip ${k === "all" ? "on" : ""}" data-f="${k}">${t}</button>`).join("")}</div>
    <span class="faint small">Click any result to see the agents' messages and the patch. Excluded = the project's own build or tests could not judge it.</span></div>
  <div class="card fade-in" style="overflow:auto">
    <table class="data">
      <thead><tr><th>CVE</th><th>Type</th>${modes.map((m) => `<th>${esc(modeName(m))}</th>`).join("")}</tr></thead>
      <tbody>${BENCH.cves.map((c, ci) => `<tr style="--i:${ci}" data-excl="${isExcl(c) ? 1 : 0}">
        <td><b>${esc(c.cve)}</b>${Object.keys(c.runs).filter((m) => MAIN_MODES.includes(m)).length > 1 ? `<button class="btn sm cmp" data-cmp="${ci}" title="Compare the approaches on this CVE">Compare</button>` : ""}</td>
        <td>${c.cwe ? `<span class="pill outline">${esc(STATUS.cwes?.[c.cwe] || c.cwe)}</span>` : `<span class="faint">—</span>`}</td>
        ${modes.map((m) => {
          const r = c.runs[m];
          return r ? `<td class="cell" data-mode="${m}" data-slug="${esc(c.slug)}" data-cve="${esc(c.cve)}">${pill(r.status)}<div class="faint small" style="margin-top:3px">${r.paths_before ?? "–"}→${r.paths_after ?? "–"} paths · ${fmtSec(r.seconds)}</div></td>`
                   : `<td><span class="faint">—</span></td>`;
        }).join("")}
      </tr>`).join("")}</tbody>
    </table>
  </div>`;
  document.querySelectorAll("td.cell").forEach((td) => (td.onclick = () => openDetail(td.dataset.mode, td.dataset.slug, td.dataset.cve)));
  document.querySelectorAll("[data-cmp]").forEach((b) => (b.onclick = () => openCompare(BENCH.cves[+b.dataset.cmp])));
  document.querySelectorAll("#chips .chip").forEach((b) => (b.onclick = () => {
    document.querySelectorAll("#chips .chip").forEach((x) => x.classList.toggle("on", x === b));
    document.querySelectorAll("table.data tbody tr").forEach((tr) => {
      tr.hidden = (b.dataset.f === "judged" && tr.dataset.excl === "1") || (b.dataset.f === "excluded" && tr.dataset.excl === "0");
    });
  }));
}

// a CVE is excluded when every approach that ran on it was excluded
const isExcl = (c) => Object.values(c.runs).every((r) => r.status === "excluded");

// one CVE, the same model, every approach side by side
async function openCompare(c) {
  const ov = document.createElement("div");
  ov.className = "overlay";
  ov.innerHTML = `<div class="drawer wide"><div class="drawer-head"><h2>${esc(c.cve)}</h2><span class="pill outline">${esc(STATUS.cwes?.[c.cwe] || c.cwe || "")}</span><span class="spacer"></span><button class="btn sm" id="close">Close</button></div><div class="pad" id="dbody"><span class="spinner"></span></div></div>`;
  document.body.appendChild(ov);
  const close = () => ov.remove();
  ov.onclick = (e) => e.target === ov && close();
  $("#close", ov).onclick = close;
  const modes = MAIN_MODES.filter((m) => c.runs[m]);
  const ds = await Promise.all(modes.map((m) => api(`/api/benchmark/${m}/${encodeURIComponent(c.slug)}`).catch(() => null)));
  const ok = (v) => (v ? "ok" : v === false ? "bad" : "gray");
  const mark = (v) => (v ? "✓" : v === false ? "✗" : "–");
  const passed = modes.filter((m, i) => (ds[i]?.row || {}).status === "verified");
  const testsOnly = modes.filter((m, i) => { const r = ds[i]?.row || {}; return r.status === "plausible" && (r.pov_ok === false || r.graph_eval_ok === false); });
  const say = passed.length === 0 ? "No approach produced a verified fix for this CVE."
    : passed.length === modes.length ? "Every approach produced a verified fix for this CVE."
    : `Only ${passed.map((m) => `<b>${esc(modeName(m))}</b>`).join(" and ")} passed the hidden security checks.`;
  $("#dbody", ov).innerHTML = `
    <div class="notice ${passed.includes("full") ? "info" : ""}" style="margin-bottom:16px">${say}${testsOnly.length ? ` ${testsOnly.map((m) => esc(modeName(m))).join(" and ")} built and passed the normal tests, but the code was still vulnerable.` : ""}</div>
    <div class="cmp-grid" style="--n:${modes.length}">${modes.map((m, i) => {
      const r = ds[i]?.row || {};
      return `<div class="card cmp-col ${m === "full" ? "lead-m" : ""}">
        <div class="pad">
          <div class="row"><h3>${esc(modeName(m))}</h3><span class="spacer"></span>${pill(r.status)}</div>
          <div class="cmp-stats faint small mono">${r.paths_before ?? "–"}→${r.paths_after ?? "–"} paths · ${r.iterations ?? 0} tries · ${fmtNum((r.prompt_tokens || 0) + (r.completion_tokens || 0))} tokens · ${fmtSec(r.seconds)}</div>
          <div class="cmp-checks">
            <span class="pill ${ok(r.compile_ok)}">${mark(r.compile_ok)} Builds</span>
            <span class="pill ${ok(r.graph_eval_ok)}">${mark(r.graph_eval_ok)} Path gone</span>
            <span class="pill ${ok(r.pov_ok)}">${mark(r.pov_ok)} Attack test</span>
          </div>
        </div>
        <div class="cmp-diff">${ds[i] ? diffView(ds[i].final_diff) : `<div class="empty small">No details.</div>`}</div>
      </div>`;
    }).join("")}</div>`;
}

async function openDetail(mode, slug, cve) {
  const ov = document.createElement("div");
  ov.className = "overlay";
  ov.innerHTML = `<div class="drawer"><div class="drawer-head"><h2>${esc(cve)}</h2><span class="pill accent">${esc(modeName(mode))}</span><span class="spacer"></span><button class="btn sm" id="replay" title="Play back the saved run step by step. Works offline, no model or key.">Replay</button><button class="btn sm" id="rerun" title="Run this CVE again in this mode (uses the model)">Run again</button><button class="btn sm" id="close">Close</button></div><div class="pad" id="dbody"><span class="spinner"></span></div></div>`;
  document.body.appendChild(ov);
  const close = () => ov.remove();
  ov.onclick = (e) => e.target === ov && close();
  $("#close", ov).onclick = close;
  $("#rerun", ov).onclick = () => rerun(ov, mode, cve);
  let d;
  try { d = await api(`/api/benchmark/${mode}/${encodeURIComponent(slug)}`); }
  catch (e) { $("#dbody", ov).innerHTML = `<div class="notice bad">${esc(e.message)}</div>`; return; }
  const r = d.row || {};
  const checks = [["Compiles", r.compile_ok], ["Paths the real fix removed are gone", r.graph_eval_ok], ["Developers' security tests (PoV)", r.pov_ok]];
  const tabs = [["Taint paths", "paths"], ["Final patch", "diff"], [`Tries (${d.tries.length})`, "tries"], ["Plan", "plan"], ["Conversation", "conv"]];
  $("#dbody", ov).innerHTML = `
    <div class="grid g4" style="margin-bottom:18px">
      <div class="card metric"><div class="label">Outcome</div><div style="margin-top:8px">${pill(r.status)}</div><div class="sub">stopped at ${esc(r.stage || "–")}</div></div>
      <div class="card metric"><div class="label">Taint paths</div><div class="value">${r.paths_before ?? "–"} → ${r.paths_after ?? "–"}</div></div>
      <div class="card metric"><div class="label">Tries · time</div><div class="value">${r.iterations ?? 0}</div><div class="sub">${fmtSec(r.seconds)}</div></div>
      <div class="card metric"><div class="label">Tokens</div><div class="value" style="font-size:24px">${fmtNum((r.prompt_tokens || 0) + (r.completion_tokens || 0))}</div><div class="sub">${r.llm_calls || 0} model calls</div></div>
    </div>
    <div class="card pad row" style="margin-bottom:18px">${checks.map(([k, v]) => `<span class="pill ${v ? "ok" : v === false ? "bad" : "gray"}">${v ? "✓" : v === false ? "✗" : "–"} ${k}</span>`).join("")}
      ${r.error ? `<div class="notice bad small" style="width:100%">${esc(String(r.error).slice(0, 400))}</div>` : ""}</div>
    <div class="card"><div class="tabs">${tabs.map(([t, k], i) => `<button data-k="${k}" class="${i ? "" : "on"}">${t}</button>`).join("")}</div><div class="pad" id="tab"></div></div>`;
  const panes = {
    paths: () => d.paths.length ? `<div class="grid g2">${d.paths.map((p) => `<div><div class="faint small mono" style="margin-bottom:8px">${esc(p.cls)}.${esc(p.method)}</div>${pathGraph(p, r.status === "verified")}</div>`).join("")}</div>` : `<div class="empty">No taint path was found on the vulnerable code.</div>`,
    diff: () => diffView(d.final_diff),
    tries: () => d.tries.length ? d.tries.map((t) => `<details class="try" ${t.try === d.tries.length ? "open" : ""}><summary>Try ${t.try} ${pill(t.status)}<span class="faint small">${esc(t.stage)}</span></summary><div>${t.feedback ? `<pre class="fb">${esc(t.feedback)}</pre>` : ""}${diffView(t.diff)}</div></details>`).join("") : `<div class="empty">No tries recorded for this mode.</div>`,
    plan: () => d.plan ? `<pre class="fb" style="max-height:none">${esc(d.plan)}</pre>` : `<div class="empty">This mode has no Planner.</div>`,
    conv: () => d.conversation.length ? `<div class="timeline">${d.conversation.map((m) => `<div class="tl ${m.role}"><div class="who">${WHO[m.role] || m.role}</div><div class="what">${esc(m.reply)}</div></div>`).join("")}</div>` : `<div class="empty">No conversation recorded.</div>`,
  };
  $("#replay", ov).onclick = () => replay(ov, d, mode, cve);
  const show = (k) => { $("#tab", ov).innerHTML = panes[k](); ov.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("on", b.dataset.k === k)); };
  ov.querySelectorAll(".tabs button").forEach((b) => (b.onclick = () => show(b.dataset.k)));
  show("paths");
}

// offline demo: play a saved run back through the same agent timeline as a live repair
async function replay(ov, d, mode, cve) {
  const r = d.row || {};
  const body = $("#dbody", ov);
  body.innerHTML = `<div class="card frame"><div class="card-head"><span class="spinner"></span><h3>Replay · ${esc(cve)} · ${esc(modeName(mode))}</h3><span class="spacer"></span>
    <div class="agents-bar">${AGENTS.map(([k, n]) => `<span class="agent" data-a="${k}">${n}</span>`).join("")}</div>
    <button class="btn sm" id="skip">Skip</button></div><div class="pad"><div class="notice small" style="margin-bottom:12px">Saved run played back offline. No model is called.</div><div class="timeline" id="rtl"></div></div></div>`;
  const tl = $("#rtl", body);
  let fast = false;
  $("#skip", body).onclick = () => (fast = true);
  const events = [{ stage: "graph", text: `${r.paths_before ?? 0} taint path(s) found on the vulnerable code.` }];
  let coder = 0;
  for (const m of d.conversation) {
    const stage = m.role === "rule" ? "coder" : m.role;
    events.push({ stage, text: m.role === "rule" ? "Rule-based fix (no model):\n\n" + m.reply : m.reply });
    if (stage === "coder") {
      const t = d.tries[coder++];
      if (t) events.push({ stage: "check", text: `Try ${t.try}: **${t.status}** (${t.stage})${t.feedback ? "\n\n" + t.feedback.slice(0, 1200) : ""}` });
    }
  }
  events.push({ stage: "check", text: `Final verdict: **${r.status}**. Paths ${r.paths_before ?? "–"} → ${r.paths_after ?? "–"} · builds ${r.compile_ok ? "yes" : "no"} · real-fix paths gone ${r.graph_eval_ok ? "yes" : r.graph_eval_ok === false ? "no" : "–"} · ${fmtSec(r.seconds)} in the original run.` });
  for (const e of events) {
    tl.insertAdjacentHTML("beforeend", `<div class="tl ${e.stage} fade-in"><div class="who">${WHO[e.stage] || e.stage}</div><div class="what">${md(e.text.length > 3000 ? e.text.slice(0, 3000) + "\n…" : e.text)}</div></div>`);
    tl.lastElementChild.scrollIntoView({ block: "nearest" });
    ov.querySelectorAll(".agent").forEach((a) => {
      if (a.dataset.a === e.stage) a.classList.add("on");
      else if (a.classList.contains("on")) { a.classList.remove("on"); a.classList.add("done"); }
    });
    if (!fast) await new Promise((res) => setTimeout(res, 1400));
  }
  $(".spinner", body)?.remove();
  $("#skip", body).textContent = "Back";
  $("#skip", body).onclick = () => { ov.remove(); openDetail(mode, d.row?.slug || "", cve); };
}

async function rerun(ov, mode, cve) {
  if (!confirm(`Run ${cve} again in mode "${modeName(mode)}"? Don't do this while daily_run.ps1 is running.`)) return;
  const body = $("#dbody", ov);
  body.innerHTML = `<div class="card"><div class="card-head"><span class="spinner"></span><h3>Running ${esc(cve)}</h3><span class="spacer"></span><span class="faint small" id="el"></span></div><div class="pad"><div class="timeline" id="rtl"></div></div></div>`;
  try {
    const job = await api("/api/benchmark/run", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ cve, mode }) });
    const j = await followJob(job.id, $("#rtl", ov), $("#el", ov));
    $(".card-head", body).innerHTML = `${pill(j.status === "done" ? (j.result?.row?.status || "verified") : "error")}<h3>Run finished</h3>`;
    body.insertAdjacentHTML("afterbegin", j.status === "done" ? `<div class="notice info" style="margin-bottom:12px">Finished: ${esc(j.result?.row?.status || "")}. Close this panel to see the updated table.</div>` : `<div class="notice bad" style="margin-bottom:12px">${esc(j.result?.error || "The run failed.")}</div>`);
  } catch (e) { body.innerHTML = `<div class="notice bad">${esc(e.message)}</div>`; }
  $("#close", ov).onclick = () => { ov.remove(); benchmarkPage(); };
}

// ------------------------------------------------------------------ Results

const COLORS = { verified: "var(--ok)", plausible: "var(--warn)", rejected: "var(--bad)", error: "var(--faint)" };

function stackedBars(rows) {
  const W = 760, rowH = 46, left = 220, H = rows.length * rowH + 30;
  const max = Math.max(1, ...rows.map((r) => r.verified + r.plausible + r.rejected + r.error));
  const scale = (W - left - 20) / max;
  const bars = rows.map((r, i) => {
    let x = left;
    const y = i * rowH + 8;
    const segs = ["verified", "plausible", "rejected", "error"].map((k) => {
      const w = r[k] * scale;
      const seg = w > 0 ? `<rect x="${x}" y="${y}" width="${w}" height="26" rx="2" fill="${COLORS[k]}"><title>${k}: ${r[k]}</title></rect>${w > 22 ? `<text x="${x + w / 2}" y="${y + 17}" text-anchor="middle" style="fill:#fff;font-weight:600">${r[k]}</text>` : ""}` : "";
      x += w;
      return seg;
    }).join("");
    return `<g><text x="${left - 12}" y="${y + 17}" text-anchor="end" style="fill:var(--text);font-weight:550">${esc(r.name)}</text>${segs}</g>`;
  }).join("");
  const ticks = Array.from({ length: max + 1 }, (_, i) => i).filter((i) => max <= 15 || i % 5 === 0)
    .map((i) => `<line class="axis" x1="${left + i * scale}" x2="${left + i * scale}" y1="0" y2="${H - 22}" stroke-dasharray="2 4"/><text x="${left + i * scale}" y="${H - 6}" text-anchor="middle">${i}</text>`).join("");
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Outcome per approach">${ticks}${bars}</svg>`;
}

async function resultsPage() {
  const b = await api("/api/benchmark");
  if (!b.summary.length) {
    view.innerHTML = `<div class="card empty"><h3>No results yet</h3><p>They appear here as soon as runs finish.</p></div>`;
    return;
  }
  const order = (m) => { const i = ["full", "seeded", "nograph", "agent", "single", "rule", "filectx", "nogate", "oracle", "noop"].indexOf(m); return i < 0 ? 99 : i; };
  const rows = b.summary.slice().sort((a, c) => order(a.mode) - order(c.mode));
  const pct = (r) => (r.judged ? Math.round((100 * r.verified) / r.judged) : 0);
  const hasCost = rows.some((r) => r.cost_per_fix != null);
  view.innerHTML = `
  <div class="page-title fade-in"><h2>Results</h2><p>Same CVEs · same model · same validator</p>
    <div class="meaning"><span>${pill("verified")} builds, tests pass, attack path gone</span><span>${pill("plausible")} tests pass, but still vulnerable</span><span>${pill("rejected")} no working patch</span></div></div>
  <div class="grid ${rows.filter((r) => MAIN_MODES.includes(r.mode)).length > 3 ? "g4" : "g3"} fade-in">
    ${rows.filter((r) => MAIN_MODES.includes(r.mode)).map((r) => `<div class="card metric reveal ${r.mode === "full" ? "lead-m" : ""}"><div class="label">${esc(r.name)}</div><div class="value ${r.mode === "full" ? "grad-text" : ""}" data-count>${pct(r)}%</div><div class="sub">${r.verified}/${r.judged} verified · ${r.still_vulnerable} still vulnerable${r.excluded ? ` · ${r.excluded} excluded` : ""}</div></div>`).join("")}
  </div>
  <div class="card pad section fade-in" style="margin-top:18px">
    <div class="row" style="margin-bottom:16px"><h3>Outcome per approach</h3><span class="spacer"></span>
      <div class="legend">${Object.entries(COLORS).map(([k, c]) => `<span><i style="background:${c}"></i>${k}</span>`).join("")}</div></div>
    ${stackedBars(rows)}
  </div>
  <div class="card fade-in" style="overflow:auto;margin-top:18px">
    <table class="data">
      <thead><tr><th>Approach</th><th class="num">Verified</th><th class="num">Plausible</th><th class="num">Rejected</th><th class="num">Errors</th><th class="num" title="Build and tests pass, but a security check fails">Still vulnerable</th><th class="num">Tokens</th><th class="num">Time</th><th class="num" title="All judged runs of this approach divided by its verified fixes">Tokens per fix</th><th class="num" title="All judged runs of this approach divided by its verified fixes">Time per fix</th>${hasCost ? `<th class="num">Cost per fix</th>` : ""}</tr></thead>
      <tbody>${rows.map((r) => `<tr><td><b>${esc(r.name)}</b></td><td class="num">${r.verified}<span class="faint"> / ${r.judged}</span></td><td class="num">${r.plausible}</td><td class="num">${r.rejected}</td><td class="num">${r.error}</td><td class="num">${r.still_vulnerable}</td><td class="num">${fmtNum(r.median_tokens)}</td><td class="num">${fmtSec(r.median_seconds)}</td><td class="num">${r.tokens_per_fix == null ? "–" : fmtNum(Math.round(r.tokens_per_fix))}</td><td class="num">${fmtSec(r.seconds_per_fix)}</td>${hasCost ? `<td class="num">${r.cost_per_fix == null ? "–" : esc(r.currency) + r.cost_per_fix.toFixed(3)}</td>` : ""}</tr>`).join("")}</tbody>
    </table>
  </div>
  <p class="faint small" style="margin-top:10px">Tokens and time are medians per run. "Per fix" divides everything an approach spent on the judged CVEs by its verified fixes, so failed tries are counted too.${hasCost ? "" : " To add a cost column, set your price per million tokens (GP_PRICE_IN, GP_PRICE_OUT) before starting the app."}</p>`;
  animateIn();
}

// ------------------------------------------------------------------ router

const ROUTES = { "": overview, scan: scanPage, benchmark: benchmarkPage, results: resultsPage };

async function route() {
  const key = location.hash.replace(/^#\/?/, "").split("/")[0];
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.route === key));
  moveInd();
  view.classList.remove("enter");
  try { await (ROUTES[key] || overview)(); }
  catch (e) { view.innerHTML = `<div class="notice bad">${esc(e.message)}</div>`; }
  void view.offsetWidth;
  view.classList.add("enter");
  window.scrollTo(0, 0);
}

function moveInd() {
  const a = $("#nav a.active"), ind = $("#nav .ind");
  if (!ind) return;
  if (!a) { ind.style.width = "0"; return; }
  ind.style.left = `${a.offsetLeft}px`;
  ind.style.width = `${a.offsetWidth}px`;
}

const THEMES = [["graphite", "Black and orange", "#ff6b35", "#0e0e0c"], ["midnight", "Midnight blue", "#4f8cff", "#0a0f1f"],
  ["academic", "Light academic", "#0065bd", "#ffffff"], ["terminal", "Terminal green", "#39ff6a", "#050805"]];

function themePicker() {
  const cur = document.documentElement.dataset.theme;
  $("#themes").innerHTML = THEMES.map(([k, name, a, bg]) =>
    `<button class="sw ${k === cur ? "on" : ""}" data-t="${k}" title="${name}" aria-label="${name}" role="radio" aria-checked="${k === cur}" style="--a:${a};--b:${bg}"></button>`).join("");
  document.querySelectorAll("#themes .sw").forEach((b) => (b.onclick = () => {
    document.documentElement.dataset.theme = b.dataset.t;
    try { localStorage.setItem("gp-theme", b.dataset.t); } catch {}
    themePicker();
  }));
}

// tiny Markdown for agent messages: bullets, **bold**, `code`
function md(text) {
  return esc(text)
    .replace(/^\s*[*-]\s+/gm, "• ")
    .replace(/\*\*([^*]+)\*\*/g, "<b>$1</b>")
    .replace(/`([^`]+)`/g, "<code>$1</code>");
}

function toast(html) {
  document.querySelector(".toast")?.remove();
  const t = document.createElement("div");
  t.className = "toast";
  t.innerHTML = `${html}<button class="btn sm" style="display:block;margin-top:12px">Got it</button>`;
  document.body.appendChild(t);
  t.querySelector("button").onclick = () => t.remove();
}

async function init() {
  themePicker();
  try { STATUS = await api("/api/status"); } catch {}
  $("#status").innerHTML = `<span class="pill gray mono">${esc(STATUS.model || "")}</span>` +
    (STATUS.key_set ? `<span class="pill ok"><span class="dot"></span>model ready</span>` : `<button class="pill warn keyhelp" id="keyhelp"><span class="dot"></span>scan only · no API key</button>`);
  if ($("#keyhelp")) $("#keyhelp").onclick = () => toast(`<b>Scanning works without a key. Repair needs one.</b><br>In the PowerShell window running the app: press Ctrl+C, then run<br><code>$env:GEMINI_API_KEY = "your key"</code><br><code>python -m graphpatch_v2.server</code><br>No key? Open <b>Benchmark</b>, click a GraphPatch result and press <b>Replay</b> to watch a saved agent run.`);
  $(".foot").textContent = `GRAPHPATCH · ${STATUS.version || ""}`;
  window.addEventListener("hashchange", route);
  window.addEventListener("resize", moveInd);
  document.fonts?.ready.then(moveInd);
  route();
}
init();

// ------------------------------------------------------------------ Homepage (v2.19.17: pipeline layout, chosen by Lucifer)

async function homeData() {
  let bench = { summary: [], cves: [] };
  try { bench = await api("/api/benchmark"); } catch {}
  const s = Object.fromEntries(bench.summary.map((r) => [r.mode, r]));
  const pct = (m) => (s[m] && s[m].judged ? Math.round((100 * s[m].verified) / s[m].judged) : null);
  return { bench, s, pct };
}

const homeBars = (s, pct) => `<div class="hbars">${MAIN_MODES.filter((m) => s[m]).map((m) =>
  `<div class="hbar ${m === "full" ? "lead" : ""}"><span class="hn">${esc(s[m].name)}</span>
    <span class="ht"><i style="width:${pct(m)}%"></i></span><span class="hv">${pct(m)}%<small> · ${s[m].verified}/${s[m].judged}</small></span></div>`).join("")}</div>`;

// the system drawn as its real stages, then the result
async function homePipeline() {
  const { s, pct } = await homeData();
  const stages = [["Java project", "Your code, as it is", ""], ["Program graph", "Taint path: input → dangerous call", "graph"],
    ["Planner", "Reads only that path", "ag"], ["Coder", "Writes the patch", "ag"], ["Critic", "Explains a failed try", "ag"],
    ["Verifier", "Build + tests + graph re-check", "check"], ["Verified fix", "Path is gone", "done"]];
  view.innerHTML = `
  <section class="pl-head">
    <div class="eyebrow">LLM agents <b>×</b> program graphs</div>
    <h1 class="pl-title">GraphPatch</h1>
    <p class="pl-lead">A multi-agent system that repairs Java vulnerabilities and accepts a fix only when the attack path in the program graph is gone.</p>
    <div class="row"><a class="btn primary" href="#/scan">Scan a project <span class="arr">→</span></a><a class="btn" href="#/results">See the results</a></div>
  </section>
  <section class="card pad pl-flow-card"><div class="row" style="justify-content:space-between;margin-bottom:18px"><h3>How a vulnerability gets fixed</h3><span class="faint small">up to 3 tries; the Critic feeds each failure back</span></div>
    <div class="pl-flow">${stages.map(([t, d, k], i) => `${i ? '<span class="pl-arr">→</span>' : ""}<div class="pl-st ${k}"><b>${t}</b><span>${d}</span></div>`).join("")}</div>
    <div class="pl-loop"><span>↺ not verified: the Critic's notes go back to the Planner</span></div></section>
  <section class="grid g2 pl-bottom">
    <div class="card pad"><h3 style="margin-bottom:6px">Results on 9 judged CVEs</h3><p class="faint small">Same CVEs, same model, same checks</p>${homeBars(s, pct)}</div>
    <div>${attackStory()}</div>
  </section>`;
  runStory();
}
