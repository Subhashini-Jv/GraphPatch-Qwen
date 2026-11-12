import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import toast from 'react-hot-toast'
import { Code2, FileArchive, FolderGit2, Github, Package, Plus, UploadCloud } from 'lucide-react'
import { EmptyState, Field, InfoBanner, PageHeader, Panel, StatusPill } from '../components/UI'
import { api, cweShort, langList, timeAgo, tone } from '../services/api'
import { useWorkspace } from '../services/workspace'

const PLACEHOLDER = {
  java: 'public class Upload {\n  void save(String name, byte[] data) throws Exception {\n    new java.io.FileOutputStream(new java.io.File("/uploads", name)).write(data);\n  }\n}',
  python: 'import os\nfrom flask import request\n\ndef ping():\n    host = request.args.get("host")\n    os.system("ping -c 1 " + host)',
  javascript: "const { exec } = require('child_process');\napp.get('/ping', (req, res) => {\n  exec('ping -c 1 ' + req.query.host, (e, out) => res.send(out));\n});",
}
const CWES = [['all', 'All CWE catalogues'], ['CWE-022', 'CWE-22 · Path traversal'], ['CWE-078', 'CWE-78 · OS command injection'], ['CWE-079', 'CWE-79 · Cross-site scripting'], ['CWE-094', 'CWE-94 · Code injection']]

export default function Repositories() {
  const { online, scans, scanId, setScanId, addScan } = useWorkspace()
  const nav = useNavigate()
  const input = useRef(null)
  const [cwe, setCwe] = useState('all')
  const [source, setSource] = useState('zip')
  const [url, setUrl] = useState('')
  const [code, setCode] = useState('')
  const [lang, setLang] = useState('auto')
  const [busy, setBusy] = useState(false)

  const run = async (fn, label) => {
    setBusy(true)
    const t = toast.loading(`Scanning ${label}…`)
    try {
      const meta = await fn()
      addScan(meta)
      toast.success(`${meta.name}: ${meta.findings.length} taint path(s) in ${meta.files} source file(s)`, { id: t })
      nav('/scanner')
    } catch (e) { toast.error(e.message, { id: t }) } finally { setBusy(false) }
  }
  const onFile = e => { const f = e.target.files?.[0]; e.target.value = ''; if (f) run(() => api.scanZip(f, cwe), f.name) }

  return <><PageHeader eyebrow="CODEBASE MANAGEMENT" title="Repositories" description="Bring Java, Python or JavaScript projects into the workspace. Each one is scanned with the taint graph as soon as it arrives."
    action={<button className="button primary" disabled={!online || busy} onClick={() => input.current?.click()}><Plus size={16}/> Upload ZIP</button>}/>
    {online === false && <InfoBanner>The backend is offline, so nothing can be uploaded. Start it with <b>python -m graphpatch_v2.server</b>.</InfoBanner>}
    <input ref={input} type="file" accept=".zip,application/zip" hidden onChange={onFile}/>
    <div className="two-column">
      <Panel title="Add a project" subtitle="Upload, link or paste: the code is analysed on your machine, nothing leaves it except a GitHub download">
        <div className="form-stack">
          <div className="segmented">{[['zip', 'ZIP archive'], ['github', 'GitHub URL'], ['code', 'Paste code'], ['sample', 'Sample']].map(([k, l]) => <button key={k} className={source === k ? 'active' : ''} onClick={() => setSource(k)}>{l}</button>)}</div>
          <Field label="CWE catalogues"><select value={cwe} onChange={e => setCwe(e.target.value)}>{CWES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></Field>
          {source === 'zip' && <div className="upload-panel" onClick={() => !busy && input.current?.click()} role="button" tabIndex={0} onKeyDown={e => e.key === 'Enter' && input.current?.click()}>
            <div className="upload-icon"><UploadCloud size={25}/></div><h3>Upload a repository archive</h3><p>A .zip of a Java, Python or JavaScript project (up to 60 MB). It is scanned immediately.</p><span className="button secondary">Browse files</span></div>}
          {source === 'github' && <><Field label="Public GitHub repository" hint="Optionally with a branch or tag: https://github.com/owner/repo/tree/v1.2"><input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://github.com/owner/repo"/></Field>
            <button className="button primary" disabled={!online || busy || !url.trim()} onClick={() => run(() => api.scanGithub(url.trim(), cwe), url.trim())}><Github size={15}/> Download and scan</button></>}
          {source === 'code' && <><Field label="Language"><select value={lang} onChange={e => setLang(e.target.value)}>{[['auto', 'Detect automatically'], ['java', 'Java'], ['python', 'Python'], ['javascript', 'JavaScript (Node.js)']].map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></Field>
            <Field label="Source code" hint="Request data, argv and archive names are untrusted input; so are function parameters for path traversal."><textarea className="code-input" value={code} onChange={e => setCode(e.target.value)} placeholder={PLACEHOLDER[lang] || PLACEHOLDER.java}/></Field>
            <button className="button primary" disabled={!online || busy || !code.trim()} onClick={() => run(() => api.scanCode(code, cwe, lang), 'pasted code')}><Code2 size={15}/> Scan code</button></>}
          {source === 'sample' && <><div className="callout"><Package size={17}/><span>A tiny Java project with a zip-slip (path traversal) bug, bundled with GraphPatch, to try every page without your own code.</span></div>
            <button className="button primary" disabled={!online || busy} onClick={() => run(async () => api.scanZip(await api.sample(), cwe), 'the sample project')}><Package size={15}/> Scan the sample project</button></>}
        </div>
      </Panel>
      <Panel title="What GraphPatch needs" subtitle="For scanning, and for the full benchmark harness">
        <div className="requirements-grid" style={{ gridTemplateColumns: '1fr' }}>
          <div><FileArchive/><b>Source files</b><p>Java (.java), Python (.py) or JavaScript (.js, .jsx, .mjs) sources. Scanning and the repair loop here need nothing else; tests and node_modules are skipped.</p></div>
          <div><FolderGit2/><b>Vulnerable revision</b><p>For the CWE-Bench-Java experiments the harness checks out the vulnerable commit itself (Settings → Benchmark).</p></div>
          <div><Plus/><b>Build configuration</b><p>Maven or Gradle and a JDK are used by the benchmark harness for gates G1 (compile) and G2 (tests).</p></div>
        </div>
      </Panel>
    </div>
    <Panel title="Project inventory" subtitle="Every scanned project in this workspace, newest first">
      {scans.length ? <div className="table-wrap"><table className="data-table"><thead><tr><th>Project</th><th>Source files</th><th>CWEs</th><th>Taint paths</th><th>Top risk</th><th>Repair</th><th>Scanned</th><th/></tr></thead><tbody>
        {scans.map(s => <tr key={s.id} className={s.id === scanId ? 'selected' : ''}>
          <td><b>{s.name}</b><div className="mono">{s.id}</div></td><td>{s.files}<div className="mono">{langList(s.languages)}</div></td><td>{(s.cwes || []).map(cweShort).join(', ')}</td><td>{s.findings}</td><td>{s.max_risk ?? '—'}</td>
          <td>{s.fix ? <StatusPill tone={tone(s.fix.status)}>{s.fix.status}</StatusPill> : <span className="muted">—</span>}</td><td>{timeAgo(s.created)}</td>
          <td><div className="row-actions"><button className="button secondary small" onClick={() => { setScanId(s.id); nav('/scanner') }}>Findings</button><button className="button secondary small" onClick={() => { setScanId(s.id); nav('/taint-graph') }}>Graph</button></div></td></tr>)}
      </tbody></table></div> : <EmptyState icon={FolderGit2} title="No projects yet" description="Upload a ZIP, give a GitHub URL, paste code or scan the sample project."/>}
    </Panel>
  </>
}
