import { useEffect, useState } from 'react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { ChartNoAxesCombined, Download, FileJson, FlaskConical, ShieldCheck, XCircle } from 'lucide-react'
import { EmptyState, InfoBanner, PageHeader, Panel, RiskBadge, ScanPicker, StatCard } from '../components/UI'
import { api, cweShort } from '../services/api'
import { useWorkspace } from '../services/workspace'

const pct = (a, b) => (b ? `${Math.round((100 * a) / b)}%` : '—')
const axis = { tick: { fill: '#8aa0ba', fontSize: 10 }, axisLine: false, tickLine: false }

export default function Reports() {
  const { online, scans, scanId, setScanId, scan } = useWorkspace()
  const [bench, setBench] = useState(null)
  const [format, setFormat] = useState('sarif')
  useEffect(() => { if (online) api.benchmark().then(setBench).catch(() => {}) }, [online])
  const summary = bench?.summary || []
  const full = summary.find(s => s.mode === 'full')
  const byCwe = {}
  scans.forEach(s => Object.entries(s.by_cwe || {}).forEach(([c, n]) => { byCwe[c] = (byCwe[c] || 0) + n }))
  const cweChart = Object.entries(byCwe).map(([c, n]) => ({ cwe: cweShort(c), findings: n }))
  const levels = ['critical', 'high', 'medium', 'low'].map(l => ({ level: l, findings: (scan?.findings || []).filter(f => f.risk?.level === l).length }))
  const top = [...(scan?.findings || [])].sort((a, b) => (b.risk?.score || 0) - (a.risk?.score || 0)).slice(0, 5)
  const exports = { sarif: ['SARIF 2.1.0', 'graphpatch.sarif', 'For SARIF viewers, GitHub code scanning and CI systems.'], html: ['HTML report', 'report.html', 'A printable page with every finding and the repair result.'], tests: ['Attack tests (JUnit)', 'attack-tests.zip', 'One proof-of-concept test per finding, to run in your project.'] }
  const [label, file, note] = exports[format]

  return <><PageHeader eyebrow="SECURITY INTELLIGENCE" title="Security Reports" description="Benchmark verdicts, findings across your projects, and exports for the selected scan."/>
    {online === false && <InfoBanner>The backend is offline. Start it with <b>python -m graphpatch_v2.server</b>.</InfoBanner>}
    <div className="stats-grid">
      <StatCard label="Verified" icon={ShieldCheck} tone="green" value={full ? full.verified : '—'} note={full ? `${pct(full.verified, full.judged)} of ${full.judged} judged CVEs (GraphPatch full)` : 'No benchmark runs recorded'}/>
      <StatCard label="Plausible" icon={ChartNoAxesCombined} tone="amber" value={full ? full.plausible : '—'} note={full ? `${full.still_vulnerable} still vulnerable by an oracle` : 'No benchmark runs recorded'}/>
      <StatCard label="Rejected" icon={XCircle} tone="red" value={full ? full.rejected : '—'} note={full ? `${full.error} error · ${full.excluded} excluded` : 'No benchmark runs recorded'}/>
      <StatCard label="Highest risk" icon={FlaskConical} tone="blue" value={scan?.findings?.length ? Math.max(...scan.findings.map(f => f.risk?.score || 0)) : '—'} note={scan ? scan.name : 'Pick a project below'}/>
    </div>
    <Panel title="Benchmark comparison" subtitle="Every approach run on CWE-Bench-Java (results/runs.jsonl)">
      {summary.length ? <div className="table-wrap"><table className="data-table"><thead><tr><th>Approach</th><th>Judged</th><th>Verified</th><th>Plausible</th><th>Rejected</th><th>Median tokens</th><th>Median time</th><th>Tokens / verified fix</th></tr></thead><tbody>
        {summary.map(s => <tr key={s.mode}><td><b>{s.name}</b><div className="mono">{s.mode}</div></td><td>{s.judged}</td><td>{s.verified} <span className="muted">({pct(s.verified, s.judged)})</span></td><td>{s.plausible}</td><td>{s.rejected}</td>
          <td>{s.median_tokens}</td><td>{s.median_seconds}s</td><td>{s.tokens_per_fix ?? '—'}</td></tr>)}</tbody></table></div>
        : <EmptyState icon={ShieldCheck} title="No verdict records" description="Run the benchmark (run_qwen.sh or Settings → Benchmark); verdicts are read from results/runs.jsonl."/>}</Panel>
    <div className="two-column">
      <Panel title="CWE distribution" subtitle="Taint paths across every scanned project">
        {cweChart.length ? <div className="chart-box"><ResponsiveContainer width="100%" height="100%"><BarChart data={cweChart} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <CartesianGrid stroke="#1f2d42" vertical={false}/><XAxis dataKey="cwe" {...axis}/><YAxis allowDecimals={false} {...axis}/><Tooltip cursor={{ fill: '#17263b' }} contentStyle={{ background: '#172338', border: '1px solid #2a3a52', fontSize: 11 }}/><Bar dataKey="findings" fill="#49a9ef" radius={[4, 4, 0, 0]}/></BarChart></ResponsiveContainer></div>
          : <EmptyState icon={ChartNoAxesCombined} title="No findings to chart" description="Scan a project from Repositories."/>}</Panel>
      <Panel title="Risk analysis" subtitle={scan ? `${scan.name}: findings by risk level` : 'Pick a project'} action={<ScanPicker scans={scans} value={scanId} onChange={setScanId} label="Project"/>}>
        {scan?.findings?.length ? <><div className="chart-box" style={{ height: 160 }}><ResponsiveContainer width="100%" height="100%"><BarChart data={levels} margin={{ top: 8, right: 8, left: -18, bottom: 0 }}>
          <CartesianGrid stroke="#1f2d42" vertical={false}/><XAxis dataKey="level" {...axis}/><YAxis allowDecimals={false} {...axis}/><Tooltip cursor={{ fill: '#17263b' }} contentStyle={{ background: '#172338', border: '1px solid #2a3a52', fontSize: 11 }}/><Bar dataKey="findings" fill="#f0a742" radius={[4, 4, 0, 0]}/></BarChart></ResponsiveContainer></div>
          <ul className="why-list">{top.map(f => <li key={f.key}><RiskBadge risk={f.risk}/> {f.cls}.{f.method}:{f.line} → <code>{f.sink}</code></li>)}</ul></>
          : <EmptyState icon={ShieldCheck} title="No risk scores available" description={scan ? 'This project has no findings.' : 'Pick a scanned project.'}/>}</Panel>
    </div>
    <Panel title="Export report" subtitle={scan ? `For ${scan.name}` : 'Pick a project to export its findings'}>
      <div className="export-row"><div className="export-icon"><FileJson size={22}/></div><div className="export-copy"><b>{label}</b><span>{note}</span></div>
        <select value={format} onChange={e => setFormat(e.target.value)}>{Object.entries(exports).map(([k, [l]]) => <option key={k} value={k}>{l}</option>)}</select>
        {scan ? <a className="button secondary" href={api.url(`/api/scan/${scanId}/${file}`)} target={format === 'html' ? '_blank' : undefined} rel="noreferrer"><Download size={15}/> Export</a>
          : <button className="button secondary" disabled><Download size={15}/> Export</button>}</div></Panel>
  </>
}
