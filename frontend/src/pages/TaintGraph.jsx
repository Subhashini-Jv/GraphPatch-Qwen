import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Background, Controls, MarkerType, ReactFlow } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { Download, Flame, GitBranch, Info, Target } from 'lucide-react'
import { EmptyState, InfoBanner, PageHeader, Panel, RiskBadge, ScanPicker } from '../components/UI'
import { api, cweShort } from '../services/api'
import { useWorkspace } from '../services/workspace'
import { Snippet } from './Scanner'

// lay the path out left-to-right in rows of two, snaking back on every other row, so long paths stay readable
const COLS = 2
const snake = (i) => { const r = Math.floor(i / COLS), c = i % COLS; return { x: (r % 2 ? COLS - 1 - c : c) * 310, y: r * 120 } }
// which side each node's edges leave and enter by, following the snake
const sides = (i, n) => { const r = Math.floor(i / COLS), c = i % COLS, fwd = r % 2 === 0
  return { sourcePosition: c === COLS - 1 || i === n - 1 ? 'bottom' : fwd ? 'right' : 'left', targetPosition: c === 0 && r > 0 ? 'top' : fwd ? 'left' : 'right' } }
const LABEL = { source: 'SOURCE', step: 'PROPAGATION', sink: 'SINK' }

export default function TaintGraph() {
  const { online, scans, scanId, setScanId, scan } = useWorkspace()
  const [params, setParams] = useSearchParams()
  const nav = useNavigate()
  const findings = scan?.findings || []
  const key = params.get('key')
  const f = findings.find(x => x.key === key) || findings[0]
  const [picked, setPicked] = useState(null)
  const [g, setG] = useState(null)   // program-wide graph analysed with NetworkX on the backend
  useEffect(() => { setG(null); if (scanId && scan) api.graph(scanId).then(setG).catch(() => {}) }, [scanId, scan])
  useEffect(() => setPicked(null), [f?.key])

  const { nodes, edges } = useMemo(() => {
    if (!f) return { nodes: [], edges: [] }
    const nodes = f.nodes.map((n, i) => ({ id: String(i), position: snake(i), ...sides(i, f.nodes.length), style: { width: 250 }, className: `gp-node ${n.kind} ${picked === i ? 'selected' : ''}`,
      data: { label: <div><small>{LABEL[n.kind]}{n.line ? ` · line ${n.line}` : ''}</small><div>{n.text}</div></div> } }))
    const edges = f.nodes.slice(1).map((_, i) => ({ id: `e${i}`, source: String(i), target: String(i + 1), animated: true, type: 'smoothstep',
      markerEnd: { type: MarkerType.ArrowClosed, color: '#49a9ef' }, style: { stroke: '#49a9ef' } }))
    return { nodes, edges }
  }, [f, picked])

  const node = picked != null && f ? f.nodes[picked] : null
  return <><PageHeader eyebrow="PROGRAM DATA FLOW" title="Taint Graph Explorer" description="Each taint path the graph found, drawn from the untrusted source to the dangerous sink."/>
    {online === false && <InfoBanner>The backend is offline. Start it with <b>python -m graphpatch_v2.server</b>.</InfoBanner>}
    <div className="toolbar-row">
      <ScanPicker scans={scans} value={scanId} onChange={setScanId} label="Project"/>
      {findings.length > 0 && <label className="field compact"><span>Taint path</span><select value={f?.key || ''} onChange={e => setParams({ key: e.target.value })}>
        {findings.map(x => <option key={x.key} value={x.key}>{cweShort(x.cwe)} · {x.cls}.{x.method}:{x.line} → {x.sink}</option>)}</select></label>}
    </div>
    {(() => {
      const hot = (g?.hot_files || []).map(h => [h.file, h.nodes])
      const gs = g?.summary
      return <div className="explorer">
        <div>
          <Panel title="Stats" subtitle="Whole-program taint graph (NetworkX)" action={scan && <a className="panel-link" href={api.url(`/api/scan/${scanId}/taint-graph.graphml`)} title="Download as GraphML"><Download size={14}/> GraphML</a>}><div className="stat-rows">
            <div><span>Taint paths</span><b>{findings.length}</b></div><div><span>Graph nodes</span><b>{gs?.nodes ?? 0}</b></div>
            <div><span>Graph edges</span><b>{gs?.edges ?? 0}</b></div><div><span>Sources → sinks</span><b>{gs ? `${gs.sources} → ${gs.sinks}` : '0'}</b></div>
            <div><span>Sinks reachable</span><b>{gs?.reachable_sinks ?? 0}{g?.after ? ` → ${g.after.reachable_sinks}` : ''}</b></div>
            <div><span>Components</span><b>{gs?.components ?? 0}</b></div></div>
            {g?.after && <p className="muted" style={{ fontSize: 12, margin: '8px 0 0' }}>After the repair, {g.after.reachable_sinks} sink(s) are still reachable from a source.</p>}</Panel>
          <Panel title="Hot files" subtitle="Files with the most tainted statements">
            {hot.length ? <ul className="hot-files">{hot.slice(0, 10).map(([file, n]) => <li key={file} className={f?.file === file ? 'on' : ''} onClick={() => setParams({ key: findings.find(x => x.file === file).key })} title={file}><Flame size={15}/><span>{file.split('/').pop()}</span><em>{n}</em></li>)}</ul>
              : <EmptyState icon={GitBranch} title="No files" description="No taint paths in this project."/>}</Panel>
        </div>
        <div>
          <div className="graph-toolbar" style={{ borderRadius: '16px 16px 0 0' }}><div><b>{f ? `${f.cls}.${f.method}` : 'Graph canvas'}</b><span>{f ? `${cweShort(f.cwe)} ${f.cwe_name} · ${f.file}` : 'Source → propagation → sink'}</span></div>
            {f ? <RiskBadge risk={f.risk}/> : <span className="subtle-label">NO GRAPH DATA</span>}</div>
          <div className="graph-shell" style={{ borderRadius: '0 0 16px 16px' }}>
            <ReactFlow colorMode="dark" nodes={nodes} edges={edges} fitView fitViewOptions={{ padding: 0.2, maxZoom: 1.2 }} key={f?.key} onNodeClick={(_, n) => setPicked(Number(n.id))} onPaneClick={() => setPicked(null)} nodesDraggable proOptions={{ hideAttribution: true }}>
              <Background color="#22324f" gap={22}/><Controls/></ReactFlow>
            {!f && <div className="graph-empty"><div className="empty-icon"><GitBranch size={22}/></div><b>No taint graph available</b>
              <p>{scan ? 'This project has no taint paths.' : 'Pick a scanned project above, or scan one from Repositories.'}</p></div>}
          </div>
          {f && <Panel title="Method source" subtitle="Lines on the path are highlighted" className="" >{f.snippet ? <Snippet snippet={f.snippet}/> : <EmptyState title="No source" description="The method could not be located."/>}</Panel>}
        </div>
        <div>
          {g?.choke_points?.length > 0 && <Panel title="Choke points" subtitle="Statements most flow passes through (betweenness centrality): one guard here breaks the most paths">
            <ul className="hot-files">{g.choke_points.map(c => <li key={c.node} title={c.node}><Target size={15} color="#38bdf8"/><span>{c.text}</span><em>{c.paths} path{c.paths > 1 ? 's' : ''}</em></li>)}</ul></Panel>}
          <Panel title={node ? `${LABEL[node.kind]}${node.line ? ` · line ${node.line}` : ''}` : 'Nothing selected'} subtitle={node ? 'Click the canvas to clear' : 'Click any node on the graph to inspect it'} className={node ? '' : 'dashed'}>
            {node ? <p className="mono" style={{ whiteSpace: 'pre-wrap', fontSize: 13 }}>{node.text}</p> : f && <ul className="path-steps">{f.nodes.map((n, i) => <li key={i} className={n.kind} style={{ cursor: 'pointer' }} onClick={() => setPicked(i)}><i/>{n.text}</li>)}</ul>}
          </Panel>
          {f && <Panel title="Why this risk score"><RiskBadge risk={f.risk}/><ul className="why-list">{(f.risk?.why || []).map((w, i) => <li key={i}>{w}</li>)}</ul>
            <div className="row-actions" style={{ marginTop: 12 }}><button className="button secondary small" onClick={() => nav('/scanner')}>Back to findings</button><button className="button primary small" onClick={() => nav('/agents')}>Repair</button></div></Panel>}
          <Panel title="Legend"><div className="legend-box"><span style={{ '--c': '#ef4444' }}><i/>Source: untrusted input</span><span style={{ '--c': '#8b5cf6' }}><i/>Propagation: assignments, fields, calls</span><span style={{ '--c': '#f59e0b' }}><i/>Sink: file, process, output or eval call</span><span style={{ '--c': '#49a9ef' }}><i/>Selected node</span></div></Panel>
        </div>
      </div>
    })()}
    <div className="callout"><Info size={17}/><span>A recognized guard (for example a normalize + startsWith containment check) breaks a path. The analysis is lightweight and flow-insensitive, so clearing the graph is gate G3, not the final verdict.</span></div>
  </>
}
