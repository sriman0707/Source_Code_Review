import React, { useState, useEffect } from 'react'
import { Bug, DollarSign, Target, Zap, ChevronRight, Copy, CheckCircle } from 'lucide-react'
import { dashboardAPI, findingsAPI, scansAPI } from '../api/client'
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer, PolarRadiusAxis } from 'recharts'

const ATTACK_TYPES = [
  { id: 'IDOR', name: 'IDOR / BOLA', emoji: '🔓', desc: 'Broken Object Level Authorization' },
  { id: 'RCE', name: 'Remote Code Execution', emoji: '💥', desc: 'Command/code injection leading to RCE' },
  { id: 'SQLi', name: 'SQL Injection', emoji: '🗄️', desc: 'Database query manipulation' },
  { id: 'AUTH', name: 'Auth Bypass', emoji: '🔑', desc: 'JWT, OAuth, MFA bypass' },
  { id: 'SSRF', name: 'SSRF', emoji: '🌐', desc: 'Server-side request forgery' },
  { id: 'XSS', name: 'XSS / Stored', emoji: '📜', desc: 'Cross-site scripting attacks' },
]

const PROGRAM_RANGES = {
  CRITICAL: { min: 5000, max: 50000 },
  HIGH: { min: 1000, max: 10000 },
  MEDIUM: { min: 300, max: 3000 },
  LOW: { min: 50, max: 500 },
}

export default function BugBounty() {
  const [topFindings, setTopFindings] = useState([])
  const [selected, setSelected] = useState(null)
  const [radarData, setRadarData] = useState([])
  const [totalPotential, setTotalPotential] = useState(0)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function load() {
      try {
        const [topRes, summRes] = await Promise.all([
          dashboardAPI.topFindings(20),
          dashboardAPI.summary(),
        ])
        const findings = topRes.data.findings || []
        setTopFindings(findings)

        // Calculate bounty potential
        let total = 0
        findings.forEach(f => {
          const range = PROGRAM_RANGES[f.severity]
          if (range) total += (range.min + range.max) / 2
        })
        setTotalPotential(total)

        // Radar chart data
        const sev = summRes.data?.severity_distribution || {}
        setRadarData([
          { subject: 'Injection', value: Math.min(100, ((sev.CRITICAL || 0) + (sev.HIGH || 0)) * 10) },
          { subject: 'Auth', value: Math.min(100, (sev.HIGH || 0) * 8) },
          { subject: 'Access Ctrl', value: Math.min(100, (sev.CRITICAL || 0) * 12) },
          { subject: 'Crypto', value: Math.min(100, (sev.MEDIUM || 0) * 5) },
          { subject: 'Config', value: Math.min(100, (sev.LOW || 0) * 3) },
          { subject: 'Data Exposure', value: Math.min(100, (sev.MEDIUM || 0) * 6) },
        ])
      } catch (e) {
        console.error(e)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  function formatBountyRange(severity) {
    const r = PROGRAM_RANGES[severity]
    if (!r) return '$0'
    return `$${r.min.toLocaleString()} – $${r.max.toLocaleString()}`
  }

  return (
    <div className="page animate-in">
      <div className="page-header">
        <div>
          <h1 className="page-title">Bug Bounty Mode</h1>
          <div className="page-subtitle">Prioritize, weaponize, and report vulnerabilities like a top bug bounty hunter</div>
        </div>
        <div style={{ background: 'var(--low-bg)', border: '1px solid rgba(34,197,94,0.3)', borderRadius: 'var(--radius-md)', padding: '10px 20px', textAlign: 'center' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Potential Bounty</div>
          <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--low)' }}>
            ${totalPotential.toLocaleString()}
          </div>
        </div>
      </div>

      {/* Attack Surface Radar */}
      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 24, marginBottom: 24 }}>
        <div className="card">
          <div className="card-title" style={{ marginBottom: 16 }}>Attack Surface Radar</div>
          <ResponsiveContainer width="100%" height={220}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="var(--border)" />
              <PolarAngleAxis dataKey="subject" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
              <PolarRadiusAxis angle={30} domain={[0, 100]} tick={false} axisLine={false} />
              <Radar name="Risk" dataKey="value" stroke="var(--accent)" fill="var(--accent)" fillOpacity={0.2} strokeWidth={2} />
            </RadarChart>
          </ResponsiveContainer>
        </div>

        {/* Attack Type Grid */}
        <div className="card">
          <div className="card-title" style={{ marginBottom: 16 }}>Vulnerability Classes Detected</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
            {ATTACK_TYPES.map(at => (
              <div key={at.id} style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: 14 }}>
                <div style={{ fontSize: '1.5rem', marginBottom: 6 }}>{at.emoji}</div>
                <div style={{ fontWeight: 700, fontSize: '0.875rem' }}>{at.name}</div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 3 }}>{at.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Bug Bounty Finding Table */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">Exploitable Findings — Sorted by Bounty Potential</div>
          <Bug size={16} color="var(--accent)" />
        </div>

        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Finding</th>
                <th>File</th>
                <th>CWE</th>
                <th>CVSS</th>
                <th>Bounty Range</th>
                <th>Report</th>
              </tr>
            </thead>
            <tbody>
              {topFindings.map(f => (
                <tr key={f.id} onClick={() => setSelected(selected?.id === f.id ? null : f)} style={{ cursor: 'pointer' }}>
                  <td><span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                  <td style={{ maxWidth: 280 }}>
                    <div style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {f.title}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{f.scan_name}</div>
                  </td>
                  <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                    {f.file_path?.split('/').pop()}:{f.line_start}
                  </td>
                  <td><span style={{ color: 'var(--accent)', fontSize: '0.8rem' }}>{f.cwe_id || '—'}</span></td>
                  <td>
                    {f.cvss_score ? (
                      <span style={{ fontWeight: 700, color: f.cvss_score >= 9 ? 'var(--critical)' : f.cvss_score >= 7 ? 'var(--high)' : 'var(--medium)' }}>
                        {f.cvss_score.toFixed(1)}
                      </span>
                    ) : '—'}
                  </td>
                  <td>
                    <span style={{ color: 'var(--low)', fontWeight: 600, fontSize: '0.8rem' }}>
                      {formatBountyRange(f.severity)}
                    </span>
                  </td>
                  <td onClick={e => e.stopPropagation()}>
                    <button className="btn btn-secondary btn-sm">
                      <Target size={12} /> Generate
                    </button>
                  </td>
                </tr>
              ))}
              {topFindings.length === 0 && (
                <tr><td colSpan={7} className="table-empty">No findings yet. Run a Bug Bounty scan first!</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* HackerOne Report Template */}
      {selected && (
        <div className="card" style={{ marginTop: 20 }}>
          <div className="card-header">
            <div className="card-title">🐛 HackerOne-Style Report Preview</div>
            <CopyReport finding={selected} />
          </div>
          <div className="code-block" style={{ fontSize: '0.8rem', lineHeight: 1.9 }}>
{`# ${selected.title}

## Summary
${selected.title}

**Severity**: ${selected.severity}
**CVSS**: ${selected.cvss_score || 'N/A'}
**CWE**: ${selected.cwe_id || 'N/A'}

## Steps to Reproduce
1. Identify the vulnerable endpoint
2. Send a crafted payload to the affected parameter
3. Observe the application's behavior
4. Confirm the vulnerability

## Proof of Concept
(AI-generated PoC available in Deep/Bug Bounty scan profiles)

## Impact
This vulnerability could allow an attacker to ${selected.category === 'injection' ? 'execute arbitrary code or access unauthorized data' : 'perform unauthorized actions'}.

## Affected Component
- File: ${selected.file_path}
- Line: ${selected.line_start}
- Category: ${selected.category}

## Remediation
Apply proper input validation, use parameterized queries, and follow OWASP secure coding guidelines.

## References
- https://owasp.org/www-project-top-ten/
- https://cwe.mitre.org/data/definitions/${selected.cwe_id?.replace('CWE-', '') || ''}.html`}
          </div>
        </div>
      )}
    </div>
  )
}

function CopyReport({ finding }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    const report = `# ${finding.title}\n\nSeverity: ${finding.severity}\nCWE: ${finding.cwe_id}\nFile: ${finding.file_path}:${finding.line_start}`
    navigator.clipboard.writeText(report)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button className="btn btn-secondary btn-sm" onClick={copy}>
      {copied ? <CheckCircle size={12} color="var(--low)" /> : <Copy size={12} />}
      {copied ? 'Copied!' : 'Copy Report'}
    </button>
  )
}
