import { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { AlertTriangle, ArrowRight, Bot, ChevronRight, FileCode2, FolderGit2, ScanSearch, ShieldCheck, ShieldEllipsis, Wrench } from 'lucide-react'
import { EmptyState, InfoBanner, Kpi, Meter, PageHeader, Panel, SEV, SeverityBar } from '../components/UI'
import { api, cweShort, langList, timeAgo } from '../services/api'
import { useWorkspace } from '../services/workspace'

const tip = { contentStyle: { background: '#0f1a30', border: '1px solid #273a5a', borderRadius: 10, fontSize: 12 }, labelStyle: { color: '#dbe5f3' } }
const axis = { tick: { fill: '#8fa6c4', fontSize: 12 }, axisLine: false, tickLine: false }

export default function Dashboard() {
  const { online, scans, setScanId } = useWorkspace()
  const nav = useNavigate()
  const [bench, setBench] = useState(null)
  useEffect(() => { if (online) api.benchmark().then(setBench).catch(() => {}) }, [online])

  const total = scans.reduce((n, s) => n + s.findings, 0)
  const remediated = scans.reduce((n, s) => n + (s.fix?.status === 'closed' ? s.fix.paths_before : s.fix?.paths_after != null ? s.fix.paths_before - s.fix.paths_after : 0), 0)
  const repairing = scans.filter(s => s.fix && s.fix.status !== 'closed').reduce((n, s) => n + (s.fix.paths_after ?? s.fix.paths_before ?? 0), 0)
  const open = Math.max(0, total - remediated - repairing)
  const levels = { critical: 0, high: 0, medium: 0, low: 0 }
  scans.forEach(s => Object.entries(s.levels || {}).forEach(([k, n]) => { levels[k] += n }))
  const byCwe = {}
  scans.forEach(s => Object.entries(s.by_cwe || {}).forEach(([c, n]) => { byCwe[c] = (byCwe[c] || 0) + n }))
  const trend = [...scans].reverse().slice(-12).map(s => ({ name: s.name.length > 12 ? s.name.slice(0, 11) + '…' : s.name, ...(s.levels || {}) }))
  const status = [{ k: 'Open', v: open, c: '#ef4444' }, { k: 'Remediated', v: remediated, c: '#22c55e' }, { k: 'Repair failed', v: repairing, c: '#f97316' }, { k: 'Projects', v: 0, c: '#3b82f6' }]
  const issues = scans.flatMap(s => (s.top || []).map(f => ({ ...f, scan: s.id, project: s.name }))).sort((a, b) => b.score - a.score).slice(0, 5)
  const full = (bench?.summary || []).find(s => s.mode === 'full')
  const files = scans.reduce((n, s) => n + (s.files || 0), 0)
  const langs = {}
  scans.forEach(s => Object.entries(s.languages || {}).forEach(([k, n]) => { langs[k] = (langs[k] || 0) + n }))
  const activity = scans.slice(0, 6).flatMap(s => [
    s.fix && { c: s.fix.status === 'closed' ? '#22c55e' : '#f97316', t: `${s.fix.engine === 'rule' ? 'Rule fix' : 'Agent repair'} ${s.fix.status}`, sub: `${s.name} · ${s.fix.paths_before} → ${s.fix.paths_after ?? '?'} paths`, when: s.created, id: s.id, to: '/patch-review' },
    { c: '#8b5cf6', t: `Scanned ${s.name}`, sub: `${s.findings} taint path${s.findings === 1 ? '' : 's'} in ${s.files} source file${s.files === 1 ? '' : 's'}`, when: s.created, id: s.id, to: '/scanner' }]).filter(Boolean).slice(0, 6)
  const go = (id, to) => { setScanId(id); nav(to) }

  return <><PageHeader eyebrow="SECURITY OVERVIEW" title="Dashboard" description="Every project in your GraphPatch workspace: taint paths, risk, and what the repairs closed."
    action={<div className="row-actions"><Link className="button secondary" to="/agents"><Bot size={16}/> Run a repair</Link><Link className="button primary" to="/repositories"><ScanSearch size={16}/> New scan</Link></div>}/>
    {online === false && <InfoBanner>The GraphPatch backend is not reachable. Start it with <b>python -m graphpatch_v2.server</b> and this page fills in by itself.</InfoBanner>}
    <div className="kpi-grid">
      <Kpi label="Projects" icon={FolderGit2} color="blue" value={online ? scans.length : '—'} note="scanned in this workspace"/>
      <Kpi label="Source files" icon={FileCode2} color="green" value={online ? files : '—'} note={langList(langs) || 'Java, Python, JavaScript'}/>
      <Kpi label="Taint paths" icon={AlertTriangle} color="red" value={online ? total : '—'} note={`${levels.critical + levels.high} critical or high`}/>
      <Kpi label="Remediated" icon={ShieldCheck} color="teal" value={online ? remediated : '—'} note="paths closed by a repair"/>
      <Kpi label="Benchmark verified" icon={ShieldEllipsis} color="amber" value={full ? `${full.verified}/${full.judged}` : '—'} note={full ? 'CWE-Bench-Java, held-out oracles' : 'no benchmark runs yet'}/>
    </div>
    <div className="grid-2-1">
      <Panel title="Vulnerability status" subtitle="Taint paths across all projects" action={<Link className="panel-link" to="/scanner">View details <ArrowRight size={14}/></Link>}>
        {total ? <div className="donut-wrap"><div className="donut-center"><ResponsiveContainer><PieChart><Pie data={status.filter(x => x.v)} dataKey="v" nameKey="k" innerRadius={72} outerRadius={100} stroke="none" paddingAngle={2} startAngle={90} endAngle={-270}>
          {status.filter(x => x.v).map(x => <Cell key={x.k} fill={x.c}/>)}</Pie><Tooltip {...tip}/></PieChart></ResponsiveContainer><div className="center"><b>{total}</b><span>Total</span></div></div>
          <div className="dot-legend">{status.slice(0, 3).map(x => <span key={x.k} style={{ '--c': x.c }}><i/>{x.k} <em>{x.v}</em></span>)}<span style={{ '--c': '#3b82f6' }}><i/>Projects <em>{scans.length}</em></span></div></div>
          : <EmptyState icon={ShieldCheck} title="No taint paths yet" description="Scan a project from Repositories."/>}
      </Panel>
      <Panel title="Taint paths by risk rating" subtitle="Per scanned project, oldest to newest" action={<Link className="panel-link" to="/reports">View details <ArrowRight size={14}/></Link>}>
        {trend.length ? <><div className="chart-box" style={{ height: 250 }}><ResponsiveContainer><AreaChart data={trend} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>{Object.entries(SEV).map(([k, c]) => <linearGradient key={k} id={`g-${k}`} x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor={c} stopOpacity={0.45}/><stop offset="100%" stopColor={c} stopOpacity={0.02}/></linearGradient>)}</defs>
          <CartesianGrid stroke="#1a2741" strokeDasharray="0"/><XAxis dataKey="name" {...axis}/><YAxis allowDecimals={false} {...axis}/><Tooltip {...tip}/>
          {Object.entries(SEV).map(([k, c]) => <Area key={k} type="monotone" dataKey={k} stroke={c} strokeWidth={2.5} fill={`url(#g-${k})`} dot={{ r: 3, fill: c }}/>)}</AreaChart></ResponsiveContainer></div>
          <div className="sev-legend">{Object.entries(SEV).map(([k, c]) => <span key={k} style={{ '--c': c }}><i/>{k[0].toUpperCase() + k.slice(1)}</span>)}</div></>
          : <EmptyState icon={AlertTriangle} title="No findings to chart" description="The chart fills from real scan results."/>}
      </Panel>
    </div>
    <div className="grid-1-1-1">
      <Panel title="Most critical findings" subtitle="Highest risk score first">
        {issues.length ? issues.map(f => <div className="issue" key={f.scan + f.key} onClick={() => go(f.scan, '/scanner')}><span className="issue-icon"><AlertTriangle size={18}/></span>
          <div className="issue-body"><b>{f.cwe_name} in {f.cls}.{f.method}</b><small>{cweShort(f.cwe)} · {f.project} · line {f.line}</small></div><span className={`score ${f.level}`}>{f.score}</span><ChevronRight size={16} color="#6b7f9c"/></div>)
          : <EmptyState icon={AlertTriangle} title="No findings" description="Nothing scanned yet."/>}
      </Panel>
      <Panel title="Findings by severity" subtitle="From the explainable 0–100 risk score">
        <SeverityBar levels={levels}/>
        <div style={{ marginTop: 24 }}>{Object.entries(byCwe).sort((a, b) => b[1] - a[1]).map(([c, n]) => <Meter key={c} label={`${cweShort(c)} share of paths`} value={n} max={total}/>)}</div>
      </Panel>
      <Panel title="Recent activity" subtitle="Scans and repairs in this workspace">
        {activity.length ? <ul className="timeline">{activity.map((a, i) => <li key={i} style={{ '--c': a.c }}><span className="node"/><div><b>{a.t}</b><a href="#" onClick={e => { e.preventDefault(); go(a.id, a.to) }}>{a.sub}</a></div><time>{timeAgo(a.when)}</time></li>)}</ul>
          : <EmptyState icon={Wrench} title="No activity yet" description="Scans and repairs appear here."/>}
      </Panel>
    </div>
    {full && <Panel title="Benchmark outcome" subtitle="GraphPatch (full) on CWE-Bench-Java" action={<Link className="panel-link" to="/validation">View details <ArrowRight size={14}/></Link>}>
      <div className="grid-1-1-1" style={{ marginBottom: 0 }}><Meter label="Verified" value={full.verified} max={full.judged}/><Meter label="Plausible" value={full.plausible} max={full.judged}/><Meter label="Rejected" value={full.rejected} max={full.judged}/></div></Panel>}
  </>
}
