import React, { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Shield, AlertTriangle, Filter, ChevronRight, ChevronDown,
  Code2, FlaskConical, GitBranch, Copy, CheckCircle, X
} from 'lucide-react'
import { findingsAPI, scansAPI } from '../api/client'
import { useToast } from '../components/Toast'

const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
const CATEGORIES = ['injection', 'xss', 'authentication', 'authorization', 'secret', 'idor', 'ssrf', 'xxe', 'business_logic', 'dependency', 'iac', 'graphql', 'misconfiguration']

function SeverityBadge({ s }) {
  return <span className={`badge badge-${s?.toLowerCase()}`}>{s}</span>
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button className="btn btn-ghost btn-sm" onClick={copy} title="Copy">
      {copied ? <CheckCircle size={12} color="var(--low)" /> : <Copy size={12} />}
    </button>
  )
}

function FindingDrawer({ finding, onClose }) {
  if (!finding) return null
  return (
    <div style={{
      position: 'fixed', right: 0, top: 0, bottom: 0, width: 600,
      background: 'var(--bg-secondary)', borderLeft: '1px solid var(--border)',
      overflowY: 'auto', zIndex: 200, padding: 24,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <div style={{ flex: 1, paddingRight: 16 }}>
          <div style={{ marginBottom: 8 }}><SeverityBadge s={finding.severity} /></div>
          <div style={{ fontWeight: 700, fontSize: '1rem', lineHeight: 1.4 }}>{finding.bug_bounty_title || finding.title}</div>
        </div>
        <button className="btn btn-ghost btn-sm" onClick={onClose}><X size={16} /></button>
      </div>

      {/* Location */}
      <div style={{ background: 'var(--bg-input)', padding: '10px 14px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)', marginBottom: 16, fontFamily: 'var(--font-mono)', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
        📁 {finding.file_path}:{finding.line_start}
        {finding.affected_function && ` — ${finding.affected_function}()`}
      </div>

      {/* Tabs */}
      {['Details', 'Code', 'AI Analysis', 'PoC', 'Fix'].map((t, i) => {
        const [activeTab, setActiveTab] = [useState('Details')[0], null]
        return null // simplified — see below
      })}

      {/* Description */}
      <Section title="Description">
        <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.7 }}>{finding.description}</div>
      </Section>

      {/* Classification */}
      <Section title="Classification">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          {[
            ['CWE', finding.cwe_id], ['OWASP', finding.owasp_category],
            ['CVSS', finding.cvss_score?.toFixed(1)], ['Detection', finding.detection_method],
          ].map(([k, v]) => v && (
            <div key={k} style={{ background: 'var(--bg-card)', padding: '8px 12px', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>{k}</div>
              <div style={{ fontSize: '0.8rem', fontWeight: 600 }}>{v}</div>
            </div>
          ))}
        </div>
      </Section>

      {/* Code Snippet */}
      {finding.code_snippet && (
        <Section title="Vulnerable Code">
          <div className="code-block">{finding.code_snippet}</div>
        </Section>
      )}

      {/* Taint Path */}
      {(finding.taint_source || finding.taint_sink) && (
        <Section title="Taint Flow">
          <div className="taint-path">
            {finding.taint_source && (
              <div className="taint-node source">
                <span style={{ fontSize: '0.7rem', color: 'var(--low)', fontWeight: 700 }}>SOURCE</span>
                <code style={{ fontSize: '0.75rem' }}>{finding.taint_source}</code>
              </div>
            )}
            <div className="taint-arrow">↓ flows to</div>
            {finding.taint_sink && (
              <div className="taint-node sink">
                <span style={{ fontSize: '0.7rem', color: 'var(--critical)', fontWeight: 700 }}>SINK</span>
                <code style={{ fontSize: '0.75rem' }}>{finding.taint_sink}</code>
              </div>
            )}
          </div>
        </Section>
      )}

      {/* AI Analysis */}
      {finding.ai_analyzed && (
        <>
          {finding.attack_scenario && (
            <Section title="Attack Scenario">
              <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.7, background: 'var(--critical-bg)', padding: 12, borderRadius: 'var(--radius-md)', borderLeft: '3px solid var(--critical)' }}>
                {finding.attack_scenario}
              </div>
            </Section>
          )}
          {finding.proof_of_concept && (
            <Section title="Proof of Concept">
              <div style={{ position: 'relative' }}>
                <div className="code-block">{finding.proof_of_concept}</div>
                <div style={{ position: 'absolute', top: 8, right: 8 }}><CopyButton text={finding.proof_of_concept} /></div>
              </div>
            </Section>
          )}
          {finding.estimated_bounty && (
            <Section title="Estimated Bug Bounty">
              <div style={{ background: 'var(--low-bg)', padding: '10px 14px', borderRadius: 'var(--radius-md)', color: 'var(--low)', fontWeight: 700, border: '1px solid rgba(34,197,94,0.3)' }}>
                💰 {finding.estimated_bounty}
              </div>
            </Section>
          )}
          {finding.ai_remediation && (
            <Section title="Remediation">
              <div style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.7 }}>{finding.ai_remediation}</div>
              {finding.secure_code_example && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--low)', marginBottom: 6 }}>✅ Secure Code Example</div>
                  <div className="code-block" style={{ borderLeft: '3px solid var(--low)' }}>{finding.secure_code_example}</div>
                </div>
              )}
            </Section>
          )}
        </>
      )}

      {/* References */}
      {finding.references?.length > 0 && (
        <Section title="References">
          {finding.references.map((r, i) => (
            <a key={i} href={r} target="_blank" rel="noreferrer" style={{ display: 'block', fontSize: '0.8rem', color: 'var(--accent)', marginBottom: 4 }}>{r}</a>
          ))}
        </Section>
      )}
    </div>
  )
}

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 20 }}>
      <div style={{ fontSize: '0.7rem', fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6 }}>
        <div style={{ width: 3, height: 12, background: 'var(--accent)', borderRadius: 2 }} />
        {title}
      </div>
      {children}
    </div>
  )
}

export default function Findings() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const toast = useToast()
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState(scanId || null)
  const [findings, setFindings] = useState([])
  const [selected, setSelected] = useState(null)
  const [filters, setFilters] = useState({ severity: '', category: '' })
  const [loading, setLoading] = useState(false)
  const [scanInfo, setScanInfo] = useState(null)
  const wsRef = useRef(null)

  // Load scan list
  useEffect(() => {
    scansAPI.list({ limit: 20 }).then(r => {
      setScans(r.data)
      if (!selectedScan && r.data[0]) setSelectedScan(r.data[0].id)
    }).catch(() => {})
  }, [])

  // Load findings when scan changes
  useEffect(() => {
    if (!selectedScan) return
    setLoading(true)
    setFindings([])
    setSelected(null)

    scansAPI.get(selectedScan).then(r => setScanInfo(r.data)).catch(() => {})

    const params = {}
    if (filters.severity) params.severity = filters.severity
    if (filters.category) params.category = filters.category

    findingsAPI.getByScan(selectedScan, { ...params, limit: 100 })
      .then(r => setFindings(r.data))
      .catch(() => toast('Failed to load findings', 'error'))
      .finally(() => setLoading(false))

    // WebSocket for live updates
    const WS_URL = (import.meta.env.VITE_WS_URL || 'ws://localhost:8000')
    if (wsRef.current) wsRef.current.close()
    const ws = new WebSocket(`${WS_URL}/api/v1/scans/${selectedScan}/progress`)
    wsRef.current = ws
    ws.onmessage = (e) => {
      const data = JSON.parse(e.data)
      if (data.status === 'completed') {
        findingsAPI.getByScan(selectedScan, { limit: 100 }).then(r => setFindings(r.data)).catch(() => {})
        scansAPI.get(selectedScan).then(r => setScanInfo(r.data)).catch(() => {})
      }
    }
    return () => ws.close()
  }, [selectedScan, filters])

  async function markFP(id) {
    await findingsAPI.update(id, { is_false_positive: true, false_positive_reason: 'Manually marked as false positive' })
    setFindings(prev => prev.filter(f => f.id !== id))
    if (selected?.id === id) setSelected(null)
    toast('Marked as false positive', 'info')
  }

  const filtered = findings.filter(f => {
    if (filters.severity && f.severity !== filters.severity) return false
    if (filters.category && f.category !== filters.category) return false
    return true
  })

  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  findings.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1 })

  return (
    <div className="page animate-in" style={{ maxWidth: 'none' }}>
      <div className="page-header">
        <div>
          <h1 className="page-title">Findings</h1>
          <div className="page-subtitle">
            {scanInfo ? (
              <span>
                <span className={`status-dot ${scanInfo.status}`} style={{ marginRight: 6 }} />
                {scanInfo.name} — {scanInfo.total_findings} findings
                {scanInfo.status === 'running' && (
                  <span style={{ marginLeft: 8, color: 'var(--accent)' }}>({scanInfo.progress}% — {scanInfo.current_phase})</span>
                )}
              </span>
            ) : 'Select a scan to view findings'}
          </div>
        </div>
        <button className="btn btn-primary" onClick={() => navigate('/scanner')}>New Scan</button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: 20 }}>
        {/* Scan List */}
        <div>
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase' }}>
              Recent Scans
            </div>
            {scans.map(s => (
              <div key={s.id}
                onClick={() => setSelectedScan(s.id)}
                style={{
                  padding: '12px 16px', cursor: 'pointer', borderBottom: '1px solid var(--border)',
                  background: selectedScan === s.id ? 'var(--accent-glow)' : 'transparent',
                  transition: 'var(--transition)',
                }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                  <div style={{ fontSize: '0.8rem', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>{s.name}</div>
                  <span className={`status-dot ${s.status}`} style={{ flexShrink: 0, marginLeft: 6 }} />
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {s.critical_count > 0 && <span className="badge badge-critical" style={{ fontSize: '0.6rem' }}>{s.critical_count} C</span>}
                  {s.high_count > 0 && <span className="badge badge-high" style={{ fontSize: '0.6rem' }}>{s.high_count} H</span>}
                  {s.medium_count > 0 && <span className="badge badge-medium" style={{ fontSize: '0.6rem' }}>{s.medium_count} M</span>}
                </div>
                {s.status === 'running' && (
                  <div className="progress-bar" style={{ marginTop: 8 }}>
                    <div className="progress-fill" style={{ width: `${s.progress}%` }} />
                  </div>
                )}
              </div>
            ))}
            {scans.length === 0 && <div className="table-empty" style={{ padding: 24 }}>No scans yet</div>}
          </div>
        </div>

        {/* Findings Panel */}
        <div>
          {/* Severity Summary */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
            {SEVERITIES.map(s => (
              <div key={s} onClick={() => setFilters(f => ({ ...f, severity: f.severity === s ? '' : s }))}
                style={{ cursor: 'pointer' }}>
                <span className={`badge badge-${s.toLowerCase()}`} style={{ padding: '6px 12px', fontSize: '0.75rem', opacity: filters.severity && filters.severity !== s ? 0.4 : 1 }}>
                  {s}: {counts[s] || 0}
                </span>
              </div>
            ))}
            <select className="input select" style={{ padding: '4px 12px', width: 'auto', fontSize: '0.8rem' }}
              value={filters.category} onChange={e => setFilters(f => ({ ...f, category: e.target.value }))}>
              <option value="">All Categories</option>
              {CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
          </div>

          {/* Table */}
          {loading ? (
            <div style={{ display: 'flex', justifyContent: 'center', padding: 48 }}>
              <div className="spinner" style={{ width: 36, height: 36 }} />
            </div>
          ) : (
            <div className="table-container">
              <table className="table">
                <thead>
                  <tr>
                    <th>Severity</th>
                    <th>Title</th>
                    <th>File</th>
                    <th>Category</th>
                    <th>CWE</th>
                    <th>Detection</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(f => (
                    <tr key={f.id} onClick={() => setSelected(f)} style={{ cursor: 'pointer' }}>
                      <td><SeverityBadge s={f.severity} /></td>
                      <td style={{ maxWidth: 280 }}>
                        <div style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</div>
                        {f.ai_analyzed && <span style={{ fontSize: '0.65rem', color: 'var(--accent-2)', background: 'rgba(139,92,246,0.1)', padding: '1px 6px', borderRadius: 4 }}>🧠 AI</span>}
                      </td>
                      <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                        {f.file_path.split('/').slice(-2).join('/')}:{f.line_start}
                      </td>
                      <td><span className="badge badge-info">{f.category}</span></td>
                      <td><span style={{ color: 'var(--accent)', fontSize: '0.8rem' }}>{f.cwe_id || '—'}</span></td>
                      <td style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{f.detection_method?.replace('_', ' ')}</td>
                      <td onClick={e => e.stopPropagation()}>
                        <button className="btn btn-ghost btn-sm" onClick={() => markFP(f.id)} title="Mark as False Positive">FP</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {filtered.length === 0 && !loading && (
                <div className="table-empty">
                  <Shield size={32} style={{ marginBottom: 12, opacity: 0.3 }} />
                  <div>{findings.length === 0 ? 'No findings detected — great work!' : 'No findings match current filters'}</div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Drawer Overlay */}
      {selected && (
        <>
          <div onClick={() => setSelected(null)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 199 }} />
          <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
        </>
      )}
    </div>
  )
}
