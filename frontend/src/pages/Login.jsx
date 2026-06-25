import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ShieldCheck, Eye, EyeOff, Lock, User } from 'lucide-react'
import { authAPI } from '../api/client'

export default function Login() {
  const navigate = useNavigate()
  const [form, setForm] = useState({ username: '', password: '' })
  const [showPass, setShowPass] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [mode, setMode] = useState('login') // 'login' | 'register'

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      if (mode === 'login') {
        const res = await authAPI.login(form.username, form.password)
        localStorage.setItem('access_token', res.data.access_token)
        localStorage.setItem('user', JSON.stringify({
          username: res.data.username,
          role: res.data.role,
          id: res.data.user_id,
        }))
        navigate('/')
      } else {
        await authAPI.register({ username: form.username, password: form.password, email: form.email || `${form.username}@example.com` })
        setMode('login')
        setError('')
      }
    } catch (err) {
      setError(err.response?.data?.detail || 'Authentication failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="auth-page">
      <div className="auth-card animate-in">
        <div className="auth-logo">
          <div style={{
            width: 56, height: 56, borderRadius: 16,
            background: 'linear-gradient(135deg, #3b82f6, #8b5cf6)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            margin: '0 auto 16px',
          }}>
            <ShieldCheck size={28} color="white" />
          </div>
          <h1>SecureReview AI</h1>
          <p>Enterprise Source Code Security Platform</p>
        </div>

        {/* Mode toggle */}
        <div className="tabs" style={{ marginBottom: 24 }}>
          <div className={`tab ${mode === 'login' ? 'active' : ''}`} onClick={() => setMode('login')}>Sign In</div>
          <div className={`tab ${mode === 'register' ? 'active' : ''}`} onClick={() => setMode('register')}>Register</div>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="input-group">
            <label className="input-label">Username</label>
            <div style={{ position: 'relative' }}>
              <User size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                className="input"
                style={{ paddingLeft: 36 }}
                placeholder="your_username"
                value={form.username}
                onChange={e => setForm(f => ({ ...f, username: e.target.value }))}
                required
              />
            </div>
          </div>

          {mode === 'register' && (
            <div className="input-group">
              <label className="input-label">Email</label>
              <input
                className="input"
                type="email"
                placeholder="you@example.com"
                value={form.email || ''}
                onChange={e => setForm(f => ({ ...f, email: e.target.value }))}
              />
            </div>
          )}

          <div className="input-group">
            <label className="input-label">Password</label>
            <div style={{ position: 'relative' }}>
              <Lock size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                className="input"
                style={{ paddingLeft: 36, paddingRight: 40 }}
                type={showPass ? 'text' : 'password'}
                placeholder="••••••••"
                value={form.password}
                onChange={e => setForm(f => ({ ...f, password: e.target.value }))}
                required
                minLength={8}
              />
              <button
                type="button"
                onClick={() => setShowPass(!showPass)}
                style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', background: 'none', color: 'var(--text-muted)', padding: 4 }}
              >
                {showPass ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>

          {error && (
            <div style={{ background: 'var(--critical-bg)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 'var(--radius-md)', padding: '10px 14px', fontSize: '0.8rem', color: 'var(--critical)', marginBottom: 16 }}>
              {error}
            </div>
          )}

          <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }} type="submit" disabled={loading}>
            {loading ? <span className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }} /> : null}
            {mode === 'login' ? 'Sign In' : 'Create Account'}
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: 20, fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          Secured by JWT • RBAC enforced • AI-powered
        </div>
      </div>
    </div>
  )
}
