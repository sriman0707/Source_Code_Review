import React, { useState, useCallback } from 'react'
import { useDropzone } from 'react-dropzone'
import { useNavigate } from 'react-router-dom'
import { Upload, Github, Folder, Zap, Shield, Brain, Bug, ChevronRight, X } from 'lucide-react'
import { scansAPI } from '../api/client'
import { useToast } from '../components/Toast'

const PROFILES = [
  { id: 'quick', emoji: '⚡', name: 'Quick', desc: 'Secrets + patterns (~30s)' },
  { id: 'standard', emoji: '🛡️', name: 'Standard', desc: 'Full SAST + taint (~2min)' },
  { id: 'deep', emoji: '🧠', name: 'Deep', desc: 'Standard + AI analysis (~5min)' },
  { id: 'bug_bounty', emoji: '🐛', name: 'Bug Bounty', desc: 'Deep + PoC generation (~8min)' },
]

const TABS = [
  { id: 'upload', label: 'File / ZIP Upload', icon: Upload },
  { id: 'github', label: 'GitHub Repository', icon: Github },
]

export default function Scanner() {
  const navigate = useNavigate()
  const toast = useToast()
  const [tab, setTab] = useState('upload')
  const [profile, setProfile] = useState('standard')
  const [scanName, setScanName] = useState('')
  const [file, setFile] = useState(null)
  const [repoUrl, setRepoUrl] = useState('')
  const [branch, setBranch] = useState('main')
  const [loading, setLoading] = useState(false)

  const onDrop = useCallback((accepted) => {
    if (accepted[0]) {
      setFile(accepted[0])
      if (!scanName) setScanName(accepted[0].name.replace(/\.[^.]+$/, ''))
    }
  }, [scanName])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
    accept: {
      'application/zip': ['.zip'],
      'text/*': ['.py', '.js', '.ts', '.java', '.php', '.go', '.rb', '.cs'],
    },
    maxSize: 50 * 1024 * 1024,
  })

  async function handleScan() {
    if (!scanName.trim()) return toast('Please provide a scan name', 'error')
    if (tab === 'upload' && !file) return toast('Please select a file', 'error')
    if (tab === 'github' && !repoUrl.trim()) return toast('Please enter a GitHub URL', 'error')

    setLoading(true)
    try {
      const fd = new FormData()
      fd.append('name', scanName)
      fd.append('profile', profile)

      let res
      if (tab === 'upload') {
        fd.append('file', file)
        res = await scansAPI.upload(fd)
      } else {
        fd.append('repo_url', repoUrl)
        fd.append('branch', branch)
        res = await scansAPI.scanGitHub(fd)
      }

      toast(`Scan started! ID: ${res.data.id.slice(0, 8)}...`, 'success')
      navigate(`/findings/${res.data.id}`)
    } catch (err) {
      toast(err.response?.data?.detail || 'Scan failed to start', 'error')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="page animate-in">
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Scanner</h1>
          <div className="page-subtitle">Upload code or connect a repository to start a security scan</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 24, alignItems: 'start' }}>
        {/* Main Panel */}
        <div>
          {/* Source Tabs */}
          <div className="card" style={{ marginBottom: 20 }}>
            <div style={{ marginBottom: 20 }}>
              <div className="card-title" style={{ marginBottom: 12 }}>Scan Source</div>
              <div className="tabs">
                {TABS.map(({ id, label, icon: Icon }) => (
                  <div key={id} className={`tab ${tab === id ? 'active' : ''}`} onClick={() => setTab(id)}>
                    <Icon size={12} style={{ display: 'inline', marginRight: 5 }} />
                    {label}
                  </div>
                ))}
              </div>
            </div>

            {tab === 'upload' ? (
              <div>
                <div {...getRootProps()} className={`dropzone ${isDragActive ? 'active' : ''}`}>
                  <input {...getInputProps()} />
                  {file ? (
                    <div>
                      <div style={{ fontSize: '1.5rem', marginBottom: 8 }}>📄</div>
                      <div style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{file.name}</div>
                      <div style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>
                        {(file.size / 1024 / 1024).toFixed(2)} MB
                      </div>
                      <button className="btn btn-ghost btn-sm" style={{ marginTop: 12 }}
                        onClick={e => { e.stopPropagation(); setFile(null) }}>
                        <X size={12} /> Remove
                      </button>
                    </div>
                  ) : (
                    <div>
                      <div className="dropzone-icon">📁</div>
                      <div className="dropzone-title">Drop your code here</div>
                      <div className="dropzone-sub">Supports .py, .js, .ts, .java, .php, .go, .rb, .cs, .zip archives</div>
                      <div style={{ marginTop: 16 }}>
                        <span className="btn btn-secondary btn-sm">Browse Files</span>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div>
                <div className="input-group">
                  <label className="input-label">GitHub Repository URL</label>
                  <div style={{ position: 'relative' }}>
                    <Github size={14} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                    <input className="input" style={{ paddingLeft: 36 }}
                      placeholder="https://github.com/owner/repo"
                      value={repoUrl} onChange={e => setRepoUrl(e.target.value)} />
                  </div>
                </div>
                <div className="input-group">
                  <label className="input-label">Branch</label>
                  <input className="input" placeholder="main" value={branch} onChange={e => setBranch(e.target.value)} />
                </div>
              </div>
            )}
          </div>

          {/* Scan Name */}
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>Scan Name</div>
            <input className="input" placeholder="e.g. API Server v2.1 — Security Review"
              value={scanName} onChange={e => setScanName(e.target.value)} />
          </div>

          {/* Scan Profile */}
          <div className="card" style={{ marginBottom: 20 }}>
            <div className="card-title" style={{ marginBottom: 16 }}>Scan Profile</div>
            <div className="profile-grid">
              {PROFILES.map(p => (
                <div key={p.id} className={`profile-card ${profile === p.id ? 'selected' : ''}`}
                  onClick={() => setProfile(p.id)}>
                  <div className="profile-emoji">{p.emoji}</div>
                  <div className="profile-name">{p.name}</div>
                  <div className="profile-desc">{p.desc}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Launch */}
          <button className="btn btn-primary btn-lg" style={{ width: '100%', justifyContent: 'center' }}
            onClick={handleScan} disabled={loading}>
            {loading ? (
              <><span className="spinner" style={{ width: 18, height: 18, borderWidth: 2 }} /> Starting Scan...</>
            ) : (
              <><Zap size={18} /> Launch Security Scan</>
            )}
          </button>
        </div>

        {/* Sidebar Info */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 16 }}>Detection Capabilities</div>
            {[
              { icon: '🔍', label: 'SAST Analysis', desc: '200+ rules across 14 languages' },
              { icon: '🌊', label: 'Taint Tracking', desc: 'Source → Sink analysis' },
              { icon: '🔒', label: 'Secret Detection', desc: '200+ patterns + entropy' },
              { icon: '🧠', label: 'AI Reasoning', desc: 'Gemini-powered FP reduction' },
              { icon: '💼', label: 'Business Logic', desc: 'IDOR, race conditions, payment bypass' },
              { icon: '📦', label: 'Dependencies', desc: 'CVE lookup via OSV.dev' },
              { icon: '☁️', label: 'IaC Scanning', desc: 'Docker, K8s, Terraform' },
            ].map(({ icon, label, desc }) => (
              <div key={label} style={{ display: 'flex', gap: 10, alignItems: 'flex-start', marginBottom: 12 }}>
                <span style={{ fontSize: '1rem', flexShrink: 0 }}>{icon}</span>
                <div>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600 }}>{label}</div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{desc}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="card" style={{ background: 'var(--accent-glow)', borderColor: 'rgba(59,130,246,0.3)' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--accent)', marginBottom: 8 }}>
              🐛 Bug Bounty Mode
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              Enables AI-powered PoC generation, HackerOne-format reports, CVSS scoring, and exploitability analysis.
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
