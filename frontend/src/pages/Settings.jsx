import { useEffect, useState } from 'react'
import toast from 'react-hot-toast'
import { Bot, Code2, Cpu, Database, FlaskConical, Play, Settings2 } from 'lucide-react'
import { Field, InfoBanner, JobLog, PageHeader, Panel, StatusPill } from '../components/UI'
import { api, tone } from '../services/api'
import { useWorkspace } from '../services/workspace'

export default function Settings() {
  const { online, status, job, follow } = useWorkspace()
  const [cve, setCve] = useState('')
  const [mode, setMode] = useState('full')
  const [cves, setCves] = useState([])
  useEffect(() => { if (online) api.benchmark().then(b => setCves((b.cves || []).map(c => c.cve))).catch(() => {}) }, [online])
  const benchJob = job?.kind === 'benchmark' ? job : null
  const running = job?.status === 'running'
  const run = async () => {
    try { follow(await api.benchmarkRun(cve.trim(), mode)) } catch (e) { toast.error(e.message) }
  }
  const modes = status?.modes || {}

  return <><PageHeader eyebrow="WORKSPACE CONFIGURATION" title="Settings" description="What the backend is configured with, and the CWE-Bench-Java benchmark harness."/>
    {online === false && <InfoBanner>The backend is offline. Start it with <b>python -m graphpatch_v2.server</b>.</InfoBanner>}
    <InfoBanner>The model and its key are read from environment variables when the backend starts, so they never reach the browser. Change them in the shell and restart the server.</InfoBanner>
    <div className="two-column">
      <Panel title="Model provider" subtitle="Used by the Planner, Coder and Critic">
        <div className="settings-row"><div className="settings-icon"><Bot size={18}/></div><div><b>Model</b><span>{status?.model || '—'}</span></div><StatusPill tone={status?.key_set ? 'success' : 'warning'}>{status ? (status.key_set ? 'ready' : 'no key') : 'unknown'}</StatusPill></div>
        <div className="settings-row"><div className="settings-icon"><Settings2 size={18}/></div><div><b>Backend</b><span>GraphPatch {status?.version || '—'} · results in {status?.results_dir || '—'}</span></div><StatusPill tone={online ? 'success' : 'danger'}>{online ? 'online' : 'offline'}</StatusPill></div>
        <pre className="code-block" style={{ padding: 12, whiteSpace: 'pre-wrap' }}>{`# Gemini (the paper's runs)
export GEMINI_API_KEY=...
# PowerShell: $env:GEMINI_API_KEY="..."

# or Qwen2.5-Coder through Ollama, no key
export GP_LLM_PROVIDER=ollama
export GP_LLM_MODEL=qwen2.5-coder-24k   # see README: ollama create ...

python -m graphpatch_v2.server`}</pre></Panel>
      <Panel title="Benchmark run" subtitle="Run one CWE-Bench-Java CVE through the harness (needs Docker or a JDK and the dataset)">
        <div className="form-stack">
          <Field label="CVE" hint="Pick one of the paper's CVEs (graphpatch_v2/paper_cves.txt)"><input list="gp-cves" value={cve} onChange={e => setCve(e.target.value)} placeholder="CVE-YYYY-NNNNN"/><datalist id="gp-cves">{cves.map(c => <option key={c} value={c}/>)}</datalist></Field>
          <Field label="Approach"><select value={mode} onChange={e => setMode(e.target.value)}>{(Object.keys(modes).length ? Object.entries(modes) : [['full', 'GraphPatch']]).map(([k, v]) => <option key={k} value={k}>{k} · {v}</option>)}</select></Field>
          <button className="button primary" disabled={!online || running || !/^CVE-\d{4}-\d+$/.test(cve.trim())} onClick={run}><Play size={15}/> Run</button>
          {benchJob && <><StatusPill tone={tone(benchJob.status)}>{benchJob.title} · {benchJob.status}</StatusPill><JobLog job={benchJob}/></>}
          <div className="callout"><FlaskConical size={17}/><span>For the whole table use <b>run_qwen.sh</b> / <b>run_qwen.ps1</b>; add <b>--paper-mode</b> to switch off every enhancement beyond the paper.</span></div>
        </div></Panel>
    </div>
    <Panel title="Analysis configuration" subtitle="Fixed by the paper's method">
      <div className="settings-row"><div className="settings-icon"><Database size={18}/></div><div><b>Java parser</b><span>javalang · the paper's analysis (fields, calls between methods), evaluated on CWE-Bench-Java</span></div><span className="settings-tag">Research stack</span></div>
      <div className="settings-row"><div className="settings-icon"><Database size={18}/></div><div><b>Python and JavaScript</b><span>Tree-sitter grammars + catalogues/python.yaml, javascript.yaml · per-function analysis, not evaluated in the paper</span></div><span className="settings-tag">Extension</span></div>
      <div className="settings-row"><div className="settings-icon"><Cpu size={18}/></div><div><b>Taint analysis</b><span>Data flow · field flow · call edges · recognized guards</span></div><span className="settings-tag">Research stack</span></div>
      <div className="settings-row"><div className="settings-icon"><Code2 size={18}/></div><div><b>Iteration budget</b><span>Maximum repair iterations: K = 3</span></div><span className="settings-tag">Paper default</span></div></Panel>
  </>
}
