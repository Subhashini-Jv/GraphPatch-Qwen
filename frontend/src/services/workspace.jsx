import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import toast from 'react-hot-toast'
import { api } from './api'

const Ctx = createContext(null)
const load = (k) => { try { return localStorage.getItem(k) || '' } catch { return '' } }
const save = (k, v) => { try { v ? localStorage.setItem(k, v) : localStorage.removeItem(k) } catch { /* private mode */ } }

export function WorkspaceProvider({ children }) {
  const [status, setStatus] = useState(null)        // /api/status, or null while unknown
  const [online, setOnline] = useState(null)        // true / false / null (checking)
  const [scans, setScans] = useState([])
  const [scanId, setScanIdState] = useState(load('gp.scan'))
  const [scan, setScan] = useState(null)            // full scan of scanId
  const [fix, setFix] = useState(null)              // saved repair result of scanId
  const [job, setJob] = useState(null)              // running repair / benchmark job
  const timer = useRef(null)

  const refresh = useCallback(async () => {
    try {
      const [s, l] = await Promise.all([api.status(), api.scans()])
      setStatus(s); setScans(l.scans); setOnline(true)
    } catch { setOnline(false) }
  }, [])

  const setScanId = useCallback((id) => { setScanIdState(id); save('gp.scan', id) }, [])

  useEffect(() => { refresh(); const t = setInterval(refresh, 15000); return () => clearInterval(t) }, [refresh])

  useEffect(() => {
    setScan(null); setFix(null)
    if (!scanId) return
    api.scan(scanId).then(setScan).catch(() => setScanId(''))
    api.fixResult(scanId).then(setFix).catch(() => setFix(null))
  }, [scanId, setScanId])

  const addScan = useCallback((meta) => { setScanId(meta.id); setScan(meta); setFix(null); refresh() }, [refresh, setScanId])

  // poll a background job (repair or benchmark run) until it ends
  const follow = useCallback((view, onDone) => {
    clearInterval(timer.current)
    setJob(view)
    let since = view.next || 0
    let events = view.events || []
    timer.current = setInterval(async () => {
      try {
        const v = await api.job(view.id, since)
        events = events.concat(v.events || []); since = v.next
        setJob({ ...v, events })
        if (v.status !== 'running') {
          clearInterval(timer.current)
          if (v.status === 'done') toast.success(`${v.title}: finished`)
          else toast.error(`${v.title}: ${(v.result && v.result.error) || 'failed'}`)
          onDone && onDone(v)
          refresh()
        }
      } catch (e) { clearInterval(timer.current); toast.error(e.message) }
    }, 1000)
  }, [refresh])

  useEffect(() => () => clearInterval(timer.current), [])

  const startFix = useCallback(async (engine, keys) => {
    if (!scanId) return
    const view = await api.fix(scanId, { engine, keys: keys && keys.length ? keys : null, max_iters: 3 })
    follow(view, () => api.fixResult(scanId).then(setFix).catch(() => {}))
  }, [scanId, follow])

  return <Ctx.Provider value={{ status, online, scans, scanId, setScanId, scan, fix, job, refresh, addScan, startFix, follow }}>{children}</Ctx.Provider>
}

export const useWorkspace = () => useContext(Ctx)
