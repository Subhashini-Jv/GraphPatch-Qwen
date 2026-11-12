import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import '../services/monaco'
import { DiffEditor } from '@monaco-editor/react'
import { Code2, Download, GitCompareArrows, ShieldCheck } from 'lucide-react'
import { EmptyState, InfoBanner, PageHeader, Panel, ScanPicker, StatusPill } from '../components/UI'
import { api, changedFiles, tone } from '../services/api'
import { useWorkspace } from '../services/workspace'

export function DiffText({ diff }) {
  if (!diff) return <EmptyState icon={GitCompareArrows} title="Empty diff" description="This patch changed nothing."/>
  return <div className="code-block">{diff.split('\n').map((l, i) => {
    const c = l.startsWith('+++') || l.startsWith('---') ? 'meta' : l.startsWith('@@') ? 'hunk' : l.startsWith('+') ? 'add' : l.startsWith('-') ? 'del' : ''
    return <div key={i} className={`diff-line ${c}`}>{l || ' '}</div>
  })}</div>
}

export default function PatchReview() {
  const { online, scans, scanId, setScanId, fix } = useWorkspace()
  const nav = useNavigate()
  const [tab, setTab] = useState('side')
  const [tryNo, setTryNo] = useState(null)
  const [file, setFile] = useState('')
  const [texts, setTexts] = useState(null)
  const tries = fix?.tries || []
  const t = tries.find(x => x.try === tryNo) || tries[tries.length - 1]
  const isFinal = t && t === tries[tries.length - 1]
  const files = changedFiles(t?.diff)
  useEffect(() => { setTryNo(null) }, [fix])
  useEffect(() => { setFile(files[0] || '') }, [t?.diff]) // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    setTexts(null)
    if (!scanId || !file || !isFinal) return
    Promise.all([api.source(scanId, file, 'original'), api.source(scanId, file, 'patched')])
      .then(([a, b]) => setTexts({ original: a.text, patched: b.text })).catch(() => setTexts(null))
  }, [scanId, file, isFinal])

  return <><PageHeader eyebrow="CODE REMEDIATION" title="Patch Review" description="Review the candidate patch against the original code before you apply it to your repository."
    action={fix && <a className="button primary" href={api.url(`/api/scan/${scanId}/patched.zip`)}><Download size={15}/> Patched project (.zip)</a>}/>
    {online === false && <InfoBanner>The backend is offline. Start it with <b>python -m graphpatch_v2.server</b>.</InfoBanner>}
    <div className="toolbar-row"><ScanPicker scans={scans} value={scanId} onChange={setScanId} label="Project"/>
      {tries.length > 1 && <label className="field compact"><span>Patch</span><select value={t?.try || ''} onChange={e => setTryNo(Number(e.target.value))}>{tries.map(x => <option key={x.try} value={x.try}>Iteration {x.try} · {x.status}</option>)}</select></label>}
      {files.length > 1 && <label className="field compact"><span>File</span><select value={file} onChange={e => setFile(e.target.value)}>{files.map(x => <option key={x}>{x}</option>)}</select></label>}</div>
    {!fix ? <Panel title="No patch yet" subtitle="Run a repair first"><EmptyState icon={GitCompareArrows} title="Nothing to review" description={scanId ? 'This project has not been repaired yet. Start a repair from the Agents page.' : 'Pick a scanned project above.'}/>
      {scanId && <div className="row-actions" style={{ justifyContent: 'center' }}><button className="button primary small" onClick={() => nav('/agents')}>Go to Agents</button></div>}</Panel> : <>
      <div className="patch-toolbar"><div><b>{file || 'No file changed'}</b><span>Iteration {t.try} of {tries.length}{isFinal ? ' (final patch)' : ''} · {fix.engine === 'rule' ? 'rule fix' : 'agents'}</span></div>
        <div className="tab-switch"><button className={tab === 'side' ? 'active' : ''} onClick={() => setTab('side')}>Side by side</button><button className={tab === 'diff' ? 'active' : ''} onClick={() => setTab('diff')}>Unified diff</button></div></div>
      <div className="editor-panel"><div className="editor-heading"><div><Code2 size={16}/><span>{tab === 'side' ? 'Original ← → Patched' : 'Unified diff'}</span></div><StatusPill tone={tone(t.status)}>{t.status} · {t.stage}</StatusPill></div>
        {tab === 'diff' || !isFinal ? <div style={{ padding: 12 }}>{!isFinal && tab === 'side' && <p className="muted">Earlier iterations were reverted, so only their diff is kept.</p>}<DiffText diff={t.diff}/></div>
          : texts ? <DiffEditor height="460px" theme="vs-dark" language="java" original={texts.original} modified={texts.patched} options={{ readOnly: true, renderSideBySide: true, minimap: { enabled: false }, fontSize: 13 }}/>
          : <div style={{ padding: 12 }}>{file ? <p className="muted">Loading the file…</p> : <DiffText diff={t.diff}/>}</div>}
      </div>
      <div className="two-column">
        <Panel title="Patch metadata" subtitle="What changed">
          <div className="kv"><span>Files changed</span><b>{files.length}</b><span>Lines added</span><b>{(t.diff || '').split('\n').filter(l => l.startsWith('+') && !l.startsWith('+++')).length}</b>
            <span>Lines removed</span><b>{(t.diff || '').split('\n').filter(l => l.startsWith('-') && !l.startsWith('---')).length}</b>
            <span>Taint paths</span><b>{fix.paths_before} → {fix.paths_after ?? '?'}</b><span>Model calls</span><b>{fix.llm_calls || 0} · {fix.tokens || 0} tokens</b></div></Panel>
        <Panel title="Review status" subtitle="Checks this patch went through">
          <p><StatusPill tone={tone(t.status)}>{t.status}</StatusPill></p><pre className="code-block" style={{ padding: 12, whiteSpace: 'pre-wrap' }}>{t.feedback}</pre>
          <div className="callout"><ShieldCheck size={17}/><span>Read the change before you apply it. Clearing the taint graph is not proof of a correct fix: build and test the patched project too.</span></div></Panel>
      </div></>}
  </>
}
