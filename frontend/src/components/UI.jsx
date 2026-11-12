import { FileSearch, Inbox } from 'lucide-react'

export function PageHeader({ eyebrow = 'WORKSPACE', title, description, action }) {
  return <div className="page-header"><div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{action && <div className="header-action">{action}</div>}</div>
}

export function Panel({ title, subtitle, action, children, className = '' }) {
  return <section className={`panel ${className}`}><div className="panel-heading"><div><h3>{title}</h3>{subtitle && <p>{subtitle}</p>}</div>{action}</div>{children}</section>
}

export function EmptyState({ title = 'No data available yet', description = 'Connect a repository or run an analysis to see results here.', icon: Icon = Inbox }) {
  return <div className="empty-state"><div className="empty-icon"><Icon size={21} /></div><strong>{title}</strong><p>{description}</p></div>
}

export function StatusPill({ children, tone = 'neutral' }) { return <span className={`status-pill ${tone}`}><i />{children}</span> }

export function StatCard({ label, value = '—', note = 'Waiting for data', icon: Icon, tone = 'blue' }) {
  return <div className="stat-card"><div className="stat-top"><span>{label}</span><span className={`stat-icon ${tone}`}><Icon size={18} /></span></div><div className="stat-value">{value}</div><div className="stat-note">{note}</div></div>
}

export function InfoBanner({ children }) { return <div className="info-banner"><FileSearch size={17} /> <span>{children}</span></div> }

export function Field({ label, children, hint }) { return <label className="field"><span>{label}</span>{children}{hint && <small>{hint}</small>}</label> }

export function ScanPicker({ scans, value, onChange, label = 'Scan' }) {
  return <label className="field compact"><span>{label}</span><select value={value || ''} onChange={e => onChange(e.target.value)}>
    <option value="">{scans.length ? 'Select a scanned project' : 'No projects scanned yet'}</option>
    {scans.map(s => <option key={s.id} value={s.id}>{s.name} · {s.findings} finding{s.findings === 1 ? '' : 's'}</option>)}
  </select></label>
}

export function RiskBadge({ risk }) {
  if (!risk) return null
  const t = { critical: 'danger', high: 'danger', medium: 'warning', low: 'neutral' }[risk.level] || 'neutral'
  return <span className={`status-pill ${t}`} title={(risk.why || []).join('\n')}><i />{risk.score} · {risk.level}</span>
}

export function JobLog({ job }) {
  if (!job) return null
  return <div className="job-log">{(job.events || []).map((e, i) => <div key={i} className={`log-line ${e.stage}`}><span className="log-time">{e.t.toFixed(1)}s</span><span className="log-stage">{e.stage}</span><pre>{e.text}</pre></div>)}
    {job.status === 'running' && <div className="log-line running"><span className="log-time" /><span className="log-stage">…</span><pre>working</pre></div>}</div>
}

export const SEV = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6' }

export function Kpi({ label, value, note, icon: Icon, color = 'blue' }) {
  return <div className={`kpi ${color}`}><div className="kpi-head"><span className="kpi-icon"><Icon size={20}/></span>{label}</div><div className="kpi-value">{value}</div>{note && <div className="kpi-note">{note}</div>}</div>
}

export function SeverityBar({ levels }) {
  const total = Object.values(levels).reduce((a, b) => a + b, 0)
  return <><div className="sev-bar">{Object.entries(SEV).map(([k, c]) => levels[k] ? <span key={k} style={{ '--c': c, flex: levels[k] }} title={`${k}: ${levels[k]}`}/> : null)}{!total && <span style={{ '--c': '#1a2741', flex: 1 }}/>}</div>
    <div className="sev-counts">{Object.entries(SEV).map(([k, c]) => <div key={k} style={{ '--c': c }}><b>{k[0].toUpperCase() + k.slice(1)}</b><small>{levels[k] || 0}</small></div>)}</div></>
}

export function Meter({ label, value, max = 100, suffix = '%' }) {
  const pct = max ? Math.round((100 * value) / max) : 0
  return <div className="meter"><div className="meter-top"><span>{label}</span><b>{suffix === '%' ? `${pct}%` : `${value}${suffix}`}</b></div><div className="meter-track"><span style={{ width: `${Math.min(100, pct)}%` }}/></div></div>
}
