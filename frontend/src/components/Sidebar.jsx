import React from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  ShieldCheck, LayoutDashboard, ScanSearch, Bug,
  FileText, AlertTriangle, LogOut, Settings, Zap
} from 'lucide-react'

const NAV = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/scanner', icon: ScanSearch, label: 'Scanner' },
  { to: '/findings', icon: AlertTriangle, label: 'Findings' },
  { to: '/bug-bounty', icon: Bug, label: 'Bug Bounty' },
  { to: '/reports', icon: FileText, label: 'Reports' },
]

export default function Sidebar() {
  const navigate = useNavigate()
  const user = JSON.parse(localStorage.getItem('user') || '{}')

  function handleLogout() {
    localStorage.removeItem('access_token')
    localStorage.removeItem('user')
    navigate('/login')
  }

  return (
    <aside className="sidebar">
      {/* Logo */}
      <div className="sidebar-logo">
        <div className="sidebar-logo-icon">
          <ShieldCheck size={20} color="white" />
        </div>
        <div>
          <div className="sidebar-logo-text">SecureReview</div>
          <div className="sidebar-logo-sub">AI Security Platform</div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="sidebar-nav">
        <div className="nav-section-label">Main</div>
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
          >
            <Icon size={16} />
            <span>{label}</span>
          </NavLink>
        ))}

        <div className="nav-section-label" style={{ marginTop: 20 }}>Account</div>
        <div className="nav-item" style={{ cursor: 'default' }}>
          <div style={{
            width: 28, height: 28, borderRadius: '50%',
            background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: '0.7rem', fontWeight: 700, color: 'white', flexShrink: 0
          }}>
            {(user.username || 'U')[0].toUpperCase()}
          </div>
          <span style={{ fontSize: '0.8rem' }}>{user.username || 'User'}</span>
        </div>
        <button className="nav-item" onClick={handleLogout} style={{ width: '100%', textAlign: 'left' }}>
          <LogOut size={16} />
          <span>Sign out</span>
        </button>
      </nav>

      {/* Version */}
      <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border)', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <Zap size={12} color="var(--accent)" />
          v1.0.0 — Powered by Gemini AI
        </div>
      </div>
    </aside>
  )
}
