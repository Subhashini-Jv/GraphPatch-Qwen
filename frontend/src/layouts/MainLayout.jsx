import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { Activity, Bell, Bot, ChartNoAxesCombined, ChevronDown, Code2, FolderGit2, GitBranch, LayoutDashboard, Menu, ScanSearch, Settings, ShieldCheck, ShieldHalf, X } from 'lucide-react'
import { useState } from 'react'
import { useWorkspace } from '../services/workspace'

const nav = [
  { label: 'Overview', to: '/', icon: LayoutDashboard },
  { label: 'Repositories', to: '/repositories', icon: FolderGit2 },
  { label: 'Vulnerability Scanner', to: '/scanner', icon: ScanSearch },
  { label: 'Taint Graph Explorer', to: '/taint-graph', icon: GitBranch },
  { label: 'AI Agent Workspace', to: '/agents', icon: Bot },
  { label: 'Patch Review', to: '/patch-review', icon: Code2 },
  { label: 'Validation Center', to: '/validation', icon: ShieldCheck },
  { label: 'Security Reports', to: '/reports', icon: ChartNoAxesCombined },
]
const titles = { '/': 'Overview', '/repositories': 'Repositories', '/scanner': 'Vulnerability Scanner', '/taint-graph': 'Taint Graph Explorer', '/agents': 'AI Agent Workspace', '/patch-review': 'Patch Review', '/validation': 'Validation Center', '/reports': 'Security Reports', '/settings': 'Settings' }

export default function MainLayout() {
  const [mobileOpen, setMobileOpen] = useState(false)
  const { online, status } = useWorkspace()
  const dot = online === true ? 'ok' : online === false ? 'off' : ''
  const conn = online === true ? 'Backend connected' : online === false ? 'Backend offline' : 'Connecting…'
  const sub = online === true ? `${status?.model || 'no model'} · ${status?.key_set ? 'model ready' : 'no API key'}` : online === false ? 'Run: python -m graphpatch_v2.server' : 'Checking the API'
  const location = useLocation()
  const sidebar = <aside className="sidebar"><div className="brand"><div className="brand-mark"><ShieldHalf size={22} /></div><div><b>GraphPatch</b><span>SECURITY WORKSPACE</span></div><button className="mobile-close icon-button" onClick={() => setMobileOpen(false)}><X size={18}/></button></div><div className="workspace-switch"><div className="workspace-avatar">GP</div><div><b>Research workspace</b><span>{online ? 'Local backend' : 'Offline'}</span></div><ChevronDown size={15}/></div><div className="nav-label">WORKSPACE</div><nav>{nav.map(({ label, to, icon: Icon }) => <NavLink key={to} to={to} end={to === '/'} onClick={() => setMobileOpen(false)} className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}><Icon size={17}/><span>{label}</span></NavLink>)}</nav><div className="sidebar-bottom"><NavLink to="/settings" className={({isActive}) => `nav-link ${isActive ? 'active' : ''}`} onClick={() => setMobileOpen(false)}><Settings size={17}/><span>Settings</span></NavLink><div className="sidebar-status"><span className={`status-dot ${dot}`}/><div><b>{conn}</b><small>{sub}</small></div></div><div className="profile"><div className="profile-avatar">GP</div><div><b>GraphPatch</b><small>{status?.version || 'Local workspace'}</small></div><ChevronDown size={15}/></div></div></aside>
  return <div className="app-shell">{mobileOpen && <div className="mobile-scrim" onClick={() => setMobileOpen(false)} />}{mobileOpen && <div className="mobile-sidebar">{sidebar}</div>}<div className="desktop-sidebar">{sidebar}</div><main className="main-area"><header className="topbar"><div className="topbar-left"><button className="icon-button mobile-menu" onClick={() => setMobileOpen(true)}><Menu size={19}/></button><div className="breadcrumb">Workspace <span>/</span> <b>{titles[location.pathname] || 'Overview'}</b></div></div><div className="topbar-right"><span className="environment"><i className={dot}/> {online ? 'Live · local backend' : conn}</span><button className="icon-button" title="Notifications"><Bell size={18}/></button><div className="top-avatar">GP</div></div></header><div className="page-content"><Outlet /></div><footer className="footer"><span>GraphPatch <span className="muted">· Graph-verified vulnerability remediation</span></span><span>{online ? `Connected to the GraphPatch API${status?.version ? ` · ${status.version}` : ''}` : 'Backend not reachable'}</span></footer></main></div>
}
