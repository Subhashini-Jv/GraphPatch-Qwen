import { BrainCircuit, Bot, CheckCircle2, Code2, GitBranch, Loader2, MessageSquareText, ShieldCheck, Wrench, XCircle } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import { EmptyState, InfoBanner, PageHeader, Panel, ScanPicker, StatusPill } from '../components/UI'
import { ruleFixable, tone } from '../services/api'
import { useWorkspace } from '../services/workspace'

const AGENTS = [
  { name: 'Planner Agent', stage: 'planner', icon: BrainCircuit, c: '#60a5fa', idle: 'Reads the paths and plans where to break them' },
  { name: 'Coder Agent', stage: 'coder', icon: Code2, c: '#a78bfa', idle: 'Writes SEARCH/REPLACE edits' },
  { name: 'Validator', stage: 'check', icon: ShieldCheck, c: '#34d399', idle: 'Applies edits, parses Java, re-runs taint graph' },
  { name: 'Critic Agent', stage: 'critic', icon: MessageSquareText, c: '#22d3ee', idle: 'Explains a rejected patch to the Coder' },
]
const ago = (job, t) => { const s = Math.max(0, Math.round((job.elapsed || 0) - t)); return s < 60 ? `${s}s ago` : `${Math.floor(s / 60)}m ago` }
const first = (text) => (text || '').split('\n').find(l => l.trim())?.slice(0, 90) || ''

export default function Agents() {
  const { online, scans, scanId, setScanId, scan, fix, job, startFix, status } = useWorkspace()
  const nav = useNavigate()
  const fixJob = job?.kind === 'fix' ? job : null
  const running = fixJob?.status === 'running'
  const events = fixJob?.events || []
  const last = events.length ? events[events.length - 1] : null
  const tries = fix?.tries || []
  const final = tries[tries.length - 1]
  const has = (st) => events.some(e => e.stage === st)
  const rule = fix?.engine === 'rule' && !running

  // the five steps of one repair and where each one stands
  const verdictState = running ? 'todo' : final ? (final.status === 'closed' ? 'done' : 'fail') : 'todo'
  const steps = [
    { name: 'Plan', sub: rule ? 'Rule fix: no plan needed' : 'Planner reads the CWE guidance, paths and code', state: running ? (last?.stage === 'planner' && !has('coder') ? 'active' : has('planner') ? 'done' : 'todo') : fix && !rule ? 'done' : 'todo' },
    { name: 'Patch', sub: `${rule ? 'The rule adds a containment check (no model)' : 'Coder writes SEARCH/REPLACE edits'}${tries.length && !running ? ` · ${tries.length} patch${tries.length > 1 ? 'es' : ''}` : ''}`, state: running ? (last?.stage === 'coder' ? 'active' : has('coder') ? 'done' : 'todo') : fix ? 'done' : 'todo' },
    { name: 'Validate', sub: final && !running ? `${final.status} at ${final.stage} · ${final.remaining ?? '?'} path(s) left` : 'Apply edits, parse Java, re-run the taint graph', state: running ? (last?.stage === 'check' || last?.stage === 'graph' ? 'active' : has('check') ? 'done' : 'todo') : final ? (final.status === 'closed' ? 'done' : 'fail') : 'todo' },
    { name: 'Critique', sub: tries.length > 1 || has('critic') ? 'Critic sent the failure back to the Coder' : 'Only runs when a patch is rejected', state: running ? (last?.stage === 'critic' ? 'active' : has('critic') ? 'done' : 'todo') : tries.length > 1 ? 'done' : 'todo' },
    { name: 'Patched project', sub: final && !running ? (final.status === 'closed' ? 'Every selected path closed; ready to review' : 'Not closed; review the last patch') : 'Download and review the patch', state: verdictState },
  ]
  const icon = (st) => st === 'done' ? <CheckCircle2 className="ok" size={22}/> : st === 'fail' ? <XCircle className="bad" size={22}/> : st === 'active' ? <Loader2 className="run spin" size={22}/> : null

  const activity = AGENTS.map(a => {
    const ev = [...events].reverse().find(e => e.stage === a.stage || (a.stage === 'check' && e.stage === 'graph'))
    if (ev) return { ...a, text: first(ev.text), when: ago(fixJob, ev.t), live: running && last === ev ? 'busy' : 'on' }
    if (!fixJob && fix) {
      const used = a.stage === 'check' || (!rule && (a.stage !== 'critic' || tries.length > 1))
      return { ...a, text: used ? (a.stage === 'check' ? `${final.status} · ${final.stage}` : a.stage === 'planner' ? first(fix.plan) : a.stage === 'coder' ? `${tries.length} patch(es) written` : 'Critiqued the rejected patch') : rule && a.stage !== 'critic' ? 'Not used by the rule fix' : 'Not needed', when: used ? 'done' : '', live: used ? 'on' : '' }
    }
    return { ...a, text: a.idle, when: '', live: '' }
  })
  const repair = async (engine) => { try { await startFix(engine) } catch (e) { toast.error(e.message) } }
  const output = fixJob ? events.map(e => ({ st: e.stage, text: e.text })) : tries.map(t => ({ st: `try ${t.try}`, text: `${t.status} (${t.stage}) · ${first(t.feedback)}` }))

  return <><PageHeader eyebrow="MULTI-AGENT REPAIR" title="Autonomous repair pipeline" description="Plan → Patch → Validate → Critique → Patched project. Every patch is checked by re-running the taint graph."
    action={<div className="row-actions"><button className="button secondary" disabled={!scan || running || !ruleFixable(scan.findings)} onClick={() => repair('rule')} title="Java path traversal only, no model"><Wrench size={15}/> Rule fix</button>
      <button className="button primary" disabled={!scan || running || !status?.key_set || !scan.findings.length} onClick={() => repair('agents')}><Bot size={15}/> Repair with agents</button></div>}/>
    {online === false && <InfoBanner>The backend is offline. Start it with <b>python -m graphpatch_v2.server</b>.</InfoBanner>}
    {online && !status?.key_set && <InfoBanner>No model is configured on the backend, so only the rule fix can run. Set <b>GEMINI_API_KEY</b> or <b>GP_LLM_PROVIDER=ollama</b> and restart the server (see Settings).</InfoBanner>}
    <div className="toolbar-row"><ScanPicker scans={scans} value={scanId} onChange={setScanId} label="Project"/><div className="grow"/>
      <StatusPill tone={running ? 'warning' : online ? 'success' : 'neutral'}>{running ? 'Running' : online ? 'Live' : 'Offline'}</StatusPill>
      {status && <StatusPill tone={status.key_set ? 'success' : 'neutral'}>model {status.model}</StatusPill>}</div>
    <div className="grid-3-2">
      <Panel title="Repair pipeline" subtitle={fix && !running ? `${rule ? 'Rule fix' : 'Agents'} · paths ${fix.paths_before} → ${fix.paths_after ?? '?'} · ${fix.llm_calls || 0} model calls · ${fix.tokens || 0} tokens` : running ? fixJob.title : 'Pick a project and start a repair'}
        action={fix && !running && <div className="row-actions"><StatusPill tone={tone(fix.status)}>{fix.status}</StatusPill><button className="button secondary small" onClick={() => nav('/patch-review')}>Review patch</button></div>}>
        <div className="pipe">{steps.map(s => <div key={s.name} className={`pipe-step ${s.state}`}><span className="pipe-dot"/><div className="pipe-card"><div><b>{s.name}</b><small>{s.sub}</small></div>{icon(s.state)}</div></div>)}</div>
        {fix?.plan && !rule && <details style={{ marginTop: 14 }}><summary style={{ fontSize: 13, color: '#8fa6c4', cursor: 'pointer' }}>Planner’s plan</summary><pre className="code-block" style={{ padding: 12, whiteSpace: 'pre-wrap' }}>{fix.plan}</pre></details>}
      </Panel>
      <Panel title="Activity" subtitle="What each agent did last">
        <div className="activity">{activity.map(a => <div key={a.name} className="activity-item" style={{ '--c': a.c }}><span className="issue-icon"><a.icon size={20}/></span>
          <div style={{ minWidth: 0 }}><b>{a.name}</b><small style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.text}</small></div><div className="when">{a.when}<i className={a.live}/></div></div>)}</div>
      </Panel>
    </div>
    <Panel title="Output" subtitle={fixJob ? 'Live log of the running repair' : 'Result of each patch'}>
      {output.length ? <div className="console">{output.map((o, i) => <div key={i}><span className="st">[{o.st}]</span>{o.text}</div>)}{running && <div>working…</div>}</div>
        : <EmptyState icon={Bot} title="No repair yet" description={scan ? 'Start a repair above; the Planner, Coder and Critic messages stream here.' : 'Pick a scanned project first.'}/>}
    </Panel>
    <div className="callout"><GitBranch size={17}/><span>In this workspace a patch is validated by applying the edits, parsing the changed files (Java, Python or JavaScript) and re-running the taint graph. Compile (G1) and tests (G2) need the project’s build and run in the benchmark harness.</span></div>
  </>
}
