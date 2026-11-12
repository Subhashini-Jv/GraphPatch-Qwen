// All calls go to the GraphPatch FastAPI backend (graphpatch_v2/server.py).
// In development Vite proxies /api to http://localhost:8000; set VITE_API_BASE_URL to use another backend.
const BASE = (import.meta.env.VITE_API_BASE_URL || '').replace(/\/$/, '')

async function request(path, opts = {}) {
  let res
  try {
    res = await fetch(BASE + path, opts)
  } catch {
    throw new Error('Cannot reach the GraphPatch backend. Start it with: python -m graphpatch_v2.server')
  }
  const text = await res.text()
  let data = null
  try { data = text ? JSON.parse(text) : null } catch { data = text }
  if (!res.ok) throw new Error((data && data.detail) || `Request failed (${res.status})`)
  return data
}

const json = (body) => ({ method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })

export const api = {
  status: () => request('/api/status'),
  scans: () => request('/api/scans'),
  scan: (id) => request(`/api/scan/${id}`),
  scanZip: (file, cwe = 'all') => { const f = new FormData(); f.append('file', file); f.append('cwe', cwe); return request('/api/scan', { method: 'POST', body: f }) },
  scanGithub: (url, cwe = 'all') => request('/api/scan/github', json({ url, cwe })),
  scanCode: (code, cwe = 'all', language = 'auto') => request('/api/scan/code', json({ code, cwe, language })),
  sample: async () => { const r = await fetch(BASE + '/api/sample'); if (!r.ok) throw new Error('Could not load the sample project'); return new File([await r.blob()], 'sample-project.zip', { type: 'application/zip' }) },
  fix: (id, body) => request(`/api/scan/${id}/fix`, json(body)),
  fixResult: (id) => request(`/api/scan/${id}/fix`),
  source: (id, path, version) => request(`/api/scan/${id}/source?path=${encodeURIComponent(path)}&version=${version}`),
  libraries: (id) => request(`/api/scan/${id}/libraries`),
  graph: (id) => request(`/api/scan/${id}/graph`),
  job: (id, since = 0) => request(`/api/jobs/${id}?since=${since}`),
  benchmark: () => request('/api/benchmark'),
  benchmarkDetail: (mode, slug) => request(`/api/benchmark/${mode}/${slug}`),
  benchmarkRun: (cve, mode) => request('/api/benchmark/run', json({ cve, mode })),
  url: (path) => BASE + path,
}

export const CWE_LABEL = { 'CWE-022': 'Path traversal', 'CWE-078': 'OS command injection', 'CWE-079': 'Cross-site scripting', 'CWE-094': 'Code injection' }
export const LANG_LABEL = { java: 'Java', python: 'Python', javascript: 'JavaScript' }
export const langList = (l) => Object.entries(l || {}).map(([k, n]) => `${LANG_LABEL[k] || k} ${n}`).join(' · ')
// the no-model rule fix exists for Java path traversal only
export const ruleFixable = (findings) => (findings || []).some(x => x.cwe === 'CWE-022' && x.file.endsWith('.java'))
export const cweShort = (c) => (c || '').replace('CWE-0', 'CWE-')

export const tone = (status) => ({ verified: 'success', closed: 'success', done: 'success', plausible: 'warning', running: 'warning',
  rejected: 'danger', error: 'danger', failed: 'danger' }[status] || 'neutral')

export const riskTone = (level) => ({ critical: 'danger', high: 'danger', medium: 'warning', low: 'neutral' }[level] || 'neutral')

export function changedFiles(diff) {
  return [...new Set((diff || '').split('\n').filter(l => l.startsWith('+++ b/')).map(l => l.slice(6).trim()))]
}

export function timeAgo(sec) {
  if (!sec) return ''
  const d = Math.max(0, Date.now() / 1000 - sec)
  if (d < 60) return 'just now'
  if (d < 3600) return `${Math.floor(d / 60)} min ago`
  if (d < 86400) return `${Math.floor(d / 3600)} h ago`
  return new Date(sec * 1000).toLocaleDateString()
}
