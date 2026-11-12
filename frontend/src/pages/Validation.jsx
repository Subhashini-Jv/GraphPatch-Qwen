import { useEffect, useState } from 'react'
import { Check, CheckCircle2, ClipboardCheck, Code2, FileCode2, Minus, ShieldCheck, ShieldX, X } from 'lucide-react'
import { EmptyState, InfoBanner, PageHeader, Panel, ScanPicker, StatusPill } from '../components/UI'
import { api, tone } from '../services/api'
import { useWorkspace } from '../services/workspace'

// The web workspace checks a patch in three steps (no build here); the benchmark harness runs G1 compile, G2 tests, G3 graph.
const ORDER = ['apply', 'syntax', 'graph']
const GATES = [
  { id: 'apply', name: 'Edits apply', desc: 'Every SEARCH block is found in the original file and replaced.', icon: Code2 },
  { id: 'syntax', name: 'Java parses', desc: 'Each changed file still parses as Java (javalang).', icon: FileCode2 },
  { id: 'graph', name: 'Taint re-scan (G3)', desc: 'The taint graph is rebuilt; no selected source-to-sink path may remain.', icon: ShieldCheck },
]
const gateState = (t, g) => {
  if (!t) return ['not run', 'neutral']
  if (t.status === 'closed') return ['passed', 'success']
  const failed = ORDER.indexOf(t.stage), me = ORDER.indexOf(g)
  return me < failed ? ['passed', 'success'] : me === failed ? ['failed', 'danger'] : ['skipped', 'neutral']
}
const ok = (v) => v === true ? <StatusPill tone="success">pass</StatusPill> : v === false ? <StatusPill tone="danger">fail</StatusPill> : <span className="muted">—</span>

export default function Validation() {
  const { online, scans, scanId, setScanId, fix } = useWorkspace()
  const [bench, setBench] = useState(null)
  const [tryNo, setTryNo] = useState(null)
  useEffect(() => { if (online) api.benchmark().then(setBench).catch(() => {}) }, [online])
  useEffect(() => setTryNo(null), [fix])
  const tries = fix?.tries || []
  const t = tries.find(x => x.try === tryNo) || tries[tries.length - 1]
  const rows = (bench?.cves || []).flatMap(c => Object.entries(c.runs).map(([mode, r]) => ({ cve: c.cve, cwe: c.cwe, mode, ...r })))

  return <><PageHeader eyebrow="PATCH VERIFICATION" title="Validation Center" description="The in-loop checks every patch must pass, and the held-out oracles that give the final verdict."/>
    {online === false && <InfoBanner>The backend is offline. Start it with <b>python -m graphpatch_v2.server</b>.</InfoBanner>}
    <div className="toolbar-row"><ScanPicker scans={scans} value={scanId} onChange={setScanId} label="Project"/>
      {tries.length > 1 && <label className="field compact"><span>Patch</span><select value={t?.try || ''} onChange={e => setTryNo(Number(e.target.value))}>{tries.map(x => <option key={x.try} value={x.try}>Iteration {x.try} · {x.status}</option>)}</select></label>}</div>
    {(() => {
      const st = GATES.map(g => gateState(t, g.id)[1])
      const verdict = !t ? 'idle' : t.status === 'closed' ? 'pass' : 'fail'
      const node = (tn) => tn === 'success' ? '' : tn === 'danger' ? 'fail' : 'idle'
      const word = { success: <span className="pass">Passed</span>, danger: <span className="fail">Failed</span>, neutral: <span className="skip">{t ? 'Skipped' : 'Not run'}</span> }
      return <div className="hpipe">
        <div className={`hpipe-row ${t ? '' : 'idle'}`} style={{ '--n': 4 }}>
          {GATES.map((g, i) => <div className="hstep" key={g.id}><label>{['Apply', 'Parse', 'Security'][i]}</label><div className={`hnode ${node(st[i])}`}>{st[i] === 'danger' ? <X size={24}/> : st[i] === 'success' ? <Check size={24}/> : <Minus size={20}/>}</div><small>{g.name}</small></div>)}
          <div className="hstep"><label>Verdict</label><div className={`hnode ${verdict === 'pass' ? '' : verdict === 'fail' ? 'fail' : 'idle'}`}>{verdict === 'fail' ? <X size={24}/> : verdict === 'pass' ? <Check size={24}/> : <Minus size={20}/>}</div><small>{t ? t.status : 'no patch yet'}</small></div>
          <div className={`shield-badge ${verdict === 'pass' ? '' : verdict}`}>{verdict === 'fail' ? <ShieldX size={46}/> : <ShieldCheck size={46}/>}</div>
        </div>
        <div className="checklist">
          {GATES.map((g, i) => <div key={g.id}>{st[i] === 'success' ? <Check size={16} color="#4ade80"/> : st[i] === 'danger' ? <X size={16} color="#f87171"/> : <Minus size={16} color="#64748b"/>}<span>{g.name}{g.id === 'graph' && t?.remaining != null ? ` · ${t.remaining} path(s) left` : ''}</span>{word[st[i]]}</div>)}
          <div><Minus size={16} color="#64748b"/><span>Compile (G1) and tests (G2)</span><span className="skip">In the benchmark harness</span></div>
        </div>
      </div>
    })()}
    <Panel title="Validation evidence" subtitle="What the checker told the Critic for this patch">
      {t ? <pre className="code-block" style={{ padding: 12, whiteSpace: 'pre-wrap' }}>{t.feedback}</pre> : <EmptyState icon={ClipboardCheck} title="No validation evidence" description="Repair a project from the Agents page; the first failed check and its evidence appear here."/>}</Panel>
    <Panel title="Benchmark: gates and held-out oracles" subtitle="CWE-Bench-Java runs from results/runs.jsonl (G1 compile and G2 tests run in the harness)">
      {rows.length ? <div className="table-wrap"><table className="data-table"><thead><tr><th>CVE</th><th>Mode</th><th>Verdict</th><th>Stopped at</th><th>Iterations</th><th>Paths</th><th>Graph-vs-fix</th><th>PoV tests</th></tr></thead><tbody>
        {rows.map(r => <tr key={r.cve + r.mode}><td><b>{r.cve}</b><div className="mono">{r.cwe}</div></td><td>{r.mode}</td><td><StatusPill tone={tone(r.status)}>{r.status}</StatusPill></td><td>{r.stage || '—'}</td>
          <td>{r.iterations ?? '—'}</td><td>{r.paths_before ?? '—'} → {r.paths_after ?? '—'}</td><td>{ok(r.graph_eval_ok)}</td><td>{ok(r.pov_ok)}</td></tr>)}</tbody></table></div>
        : <EmptyState icon={CheckCircle2} title="No benchmark runs recorded" description="Run the harness (run_qwen.sh, or Settings → Benchmark) and each CVE's gates and oracle results appear here."/>}
      <div className="oracle-list"><div><b>Graph-versus-fix</b><p>Does the candidate remove the paths that the developers' fix removes?</p></div><div><b>Proof-of-vulnerability tests</b><p>Tests that fail on the vulnerable version and pass on the developers' fix.</p></div><div><b>CodeQL (optional)</b><p>With <code>--codeql-oracle</code>, CodeQL's own query must stop reporting the vulnerability.</p></div></div>
      <div className="mini-note">Final verdicts: Verified, Plausible or Rejected. The oracles are separate from the in-loop gates and are never shown to the agents.</div></Panel>
  </>
}
