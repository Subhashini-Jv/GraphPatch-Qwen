import { lazy, Suspense } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import MainLayout from './layouts/MainLayout'
import Dashboard from './pages/Dashboard'
import Repositories from './pages/Repositories'
import Scanner from './pages/Scanner'
import TaintGraph from './pages/TaintGraph'
import Agents from './pages/Agents'
// Monaco is large, so the Patch Review page loads on first visit
const PatchReview = lazy(() => import('./pages/PatchReview'))
import Validation from './pages/Validation'
import Reports from './pages/Reports'
import Settings from './pages/Settings'

export default function App() {
  return <Routes><Route element={<MainLayout />}>
    <Route index element={<Dashboard />} />
    <Route path="repositories" element={<Repositories />} />
    <Route path="scanner" element={<Scanner />} />
    <Route path="taint-graph" element={<TaintGraph />} />
    <Route path="agents" element={<Agents />} />
    <Route path="patch-review" element={<Suspense fallback={<div className="muted">Loading the editor…</div>}><PatchReview /></Suspense>} />
    <Route path="validation" element={<Validation />} />
    <Route path="reports" element={<Reports />} />
    <Route path="settings" element={<Settings />} />
    <Route path="*" element={<Navigate to="/" replace />} />
  </Route></Routes>
}
