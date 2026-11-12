import { useEffect, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import { Bot, Download, FileJson, FlaskConical, GitBranch, Library, ScanSearch, ShieldAlert, Wrench } from 'lucide-react'
import { EmptyState, InfoBanner, PageHeader, Panel, RiskBadge, ScanPicker, StatusPill } from '../components/UI'
import { api, cweShort, langList, ruleFixable } from '../services/api'
import { useWorkspace } from '../services/workspace'

export function Snippet({ snippet }) {
  if (!snippet) return null
  return <div className="code-block">{snippet.lines.map((l, i) => { const n = snippet.start + i; return <div key={n} className={`code-line ${snippet.highlight.includes(n) ? 'hl' : ''}`}><span>{n}</span><span>{l || ' '}</span></div> })}</div>
}

export default function Scanner() {
  const { online, scans, scanId, setScanId, scan, startFix, status, job } = useWorkspace()
  const nav = useNavigate()
  const [cwe, setCwe] = useState('all')
  const [sel, setSel] = useState(null)
  const [libs, setLibs] = useState(null)
  const findings = useMemo(() => (scan?.findings || []).filter(f => cwe === 'all' || f.cwe === cwe), [scan, cwe])
  useEffect(() => { setSel(scan?.findings?.[0]?.key || null); setLibs(null); setCwe('all') }, [scan])
  const f = findings.find(x => x.key === sel) || findings[0]
  const cwes = [...new Set((scan?.findings || []).map(x => x.cwe))]
  const running = job?.status === 'running'

  const repair = async (engine, keys) => {
    try { await startFix(engine, keys); nav('/agents') } catch (e) { toast.error(e.message) }
  }
  const checkLibs = async () => {
    const t = toast.loading('Checking declared libraries against OSV.dev…')
    try { const r = await api.libraries(scanId); setLibs(r); toast.success(`${(r.vulnerable || r.findings || []).length ?? 0} vulnerable librar${((r.vulnerable || r.findings || []).length) === 1 ? 'y' : 'ies'}`, { id: t }) } catch (e) { toast.error(e.message, { id: t }) }
  }

  return <><PageHeader eyebrow="STATIC ANALYSIS" title="Vulnerability Scanner" description="Source-to-sink taint paths found by the graph, with an explainable 0–100 risk score."
    action={<button className="button primary" onClick={() => nav('/repositories')}><ScanSearch size={16}/> Scan a project</button>}/>
    {online === false && <InfoBanner>The backend is offline. Start it with <b>python -m graphpatch_v2.server</b>.</InfoBanner>}
    <div className="toolbar-row">
      <ScanPicker scans={scans} value={scanId} onChange={setScanId} label="Project"/>
      {cwes.length > 1 && <label className="field compact"><span>CWE</span><select value={cwe} onChange={e => setCwe(e.target.value)}><option value="all">All ({scan.findings.length})</option>{cwes.map(c => <option key={c} value={c}>{cweShort(c)} ({scan.findings.filter(x => x.cwe === c).length})</option>)}</select></label>}
      <div className="grow"/>
      {scan && <div className="row-actions">
        <a className="button secondary small" href={api.url(`/api/scan/${scanId}/graphpatch.sarif`)}><FileJson size={13}/> SARIF</a>
        <a className="button secondary small" href={api.url(`/api/scan/${scanId}/attack-tests.zip`)}><FlaskConical size={13}/> Attack tests</a>
        <button className="button secondary small" onClick={checkLibs}><Library size={13}/> Check libraries</button>
      </div>}
    </div>
    {!scan ? <Panel title="Scan findings" subtitle="Pick a project above or scan a new one"><EmptyState icon={ScanSearch} title="No project selected" description="Scan a project from Repositories; its taint paths appear here."/></Panel> : <>
      <div className="stats-grid">
        <div className="stat-card"><div className="stat-top"><span>Taint paths</span></div><div className="stat-value">{scan.findings.length}</div><div className="stat-note">{scan.files} source files · {langList(scan.languages) || 'Java'} · {scan.seconds}s</div></div>
        <div className="stat-card"><div className="stat-top"><span>Critical / high</span></div><div className="stat-value">{scan.findings.filter(x => ['critical', 'high'].includes(x.risk?.level)).length}</div><div className="stat-note">by risk score</div></div>
        <div className="stat-card"><div className="stat-top"><span>Files with a path</span></div><div className="stat-value">{new Set(scan.findings.map(x => x.file)).size}</div><div className="stat-note">of {scan.files}</div></div>
        <div className="stat-card"><div className="stat-top"><span>CWE catalogues</span></div><div className="stat-value">{scan.cwes.length}</div><div className="stat-note">{scan.cwes.map(cweShort).join(', ')}</div></div>
      </div>
      {scan.findings.length === 0 ? <Panel title="Scan findings"><EmptyState icon={ShieldAlert} title="No taint paths found" description="No untrusted input reaches a sink of the selected CWE catalogues without a recognized guard."/></Panel> :
      <div className="two-column">
        <Panel title="Findings" subtitle="Sorted by risk; click one to see its path" action={<div className="row-actions">
          <button className="button secondary small" disabled={running || !ruleFixable(scan.findings)} onClick={() => repair('rule')} title="Containment check for Java path traversal, no model"><Wrench size={13}/> Rule fix</button>
          <button className="button primary small" disabled={running || !status?.key_set} onClick={() => repair('agents')} title={status?.key_set ? 'Planner, Coder and Critic' : 'Set a model API key on the backend first'}><Bot size={13}/> Repair all</button></div>}>
          <div className="table-wrap"><table className="data-table"><thead><tr><th>Risk</th><th>CWE</th><th>Where</th><th>Sink</th></tr></thead><tbody>
            {findings.map(x => <tr key={x.key} className={`clickable ${f && x.key === f.key ? 'selected' : ''}`} onClick={() => setSel(x.key)}>
              <td><RiskBadge risk={x.risk}/></td><td>{cweShort(x.cwe)}</td><td><b>{x.cls}.{x.method}</b><div className="mono">{x.file.split('/').pop()}:{x.line}</div></td><td><code>{x.sink}</code></td></tr>)}
          </tbody></table></div>
        </Panel>
        {f && <Panel title={`${f.cls}.${f.method} · line ${f.line}`} subtitle={`${cweShort(f.cwe)} ${f.cwe_name} · ${f.file}`} action={<div className="row-actions">
          <button className="button secondary small" onClick={() => nav(`/taint-graph?key=${encodeURIComponent(f.key)}`)}><GitBranch size={13}/> Graph</button>
          <button className="button primary small" disabled={running || !status?.key_set} onClick={() => repair('agents', [f.key])}><Bot size={13}/> Repair this</button></div>}>
          <ul className="path-steps">{f.nodes.map((n, i) => <li key={i} className={n.kind}><i/>{n.text}</li>)}</ul>
          <div style={{ margin: '14px 0 8px' }}><RiskBadge risk={f.risk}/><ul className="why-list">{(f.risk?.why || []).map((w, i) => <li key={i}>{w}</li>)}</ul></div>
          <Snippet snippet={f.snippet}/>
        </Panel>}
      </div>}
      {libs && <Panel title="Library vulnerabilities (OSV.dev)" subtitle="Declared Maven/Gradle dependencies with known advisories">
        <pre className="code-block" style={{ padding: 12, whiteSpace: 'pre-wrap' }}>{JSON.stringify(libs, null, 2)}</pre></Panel>}
      {!status?.key_set && online && <div className="callout"><Bot size={17}/><span>Repair with agents needs a model on the backend (for example <b>GEMINI_API_KEY</b>, or <b>GP_LLM_PROVIDER=ollama</b>). The rule fix works without one. See Settings.</span></div>}
    </>}
    {scan && <div style={{ marginTop: 12 }}><a className="text-link" href={api.url(`/api/scan/${scanId}/report.html`)} target="_blank" rel="noreferrer"><Download size={13}/> Printable HTML report</a> <StatusPill>scan {scanId}</StatusPill></div>}
  </>
}
