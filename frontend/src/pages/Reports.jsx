import React, { useState, useEffect } from 'react'
import { FileText, Download, Filter, Eye } from 'lucide-react'
import { scansAPI, findingsAPI } from '../api/client'
import { format } from 'date-fns'

const REPORT_FORMATS = [
  { id: 'hackerone', label: 'HackerOne', emoji: '🟢', desc: 'H1-style vulnerability report' },
  { id: 'executive', label: 'Executive Summary', emoji: '📊', desc: 'High-level risk report for leadership' },
  { id: 'developer', label: 'Developer Report', emoji: '💻', desc: 'Technical remediation guide' },
  { id: 'sarif', label: 'SARIF / JSON', emoji: '🔧', desc: 'Machine-readable output for CI/CD' },
]

export default function Reports() {
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [format_, setFormat] = useState('hackerone')
  const [severityFilter, setSeverityFilter] = useState([])
  const [preview, setPreview] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    scansAPI.list({ limit: 30, status: 'completed' }).then(r => {
      const completed = r.data.filter(s => s.status === 'completed')
      setScans(completed)
      if (completed[0]) setSelectedScan(completed[0].id)
    }).catch(() => {})
  }, [])

  useEffect(() => {
    if (!selectedScan) return
    findingsAPI.getByScan(selectedScan, { limit: 200 }).then(r => setFindings(r.data)).catch(() => {})
  }, [selectedScan])

  function generateReport() {
    const scan = scans.find(s => s.id === selectedScan)
    const filtered = severityFilter.length
      ? findings.filter(f => severityFilter.includes(f.severity))
      : findings

    if (format_ === 'hackerone') {
      const lines = filtered.slice(0, 10).map((f, i) => `
## Finding ${i + 1}: ${f.title}

**Severity**: ${f.severity} | **CWE**: ${f.cwe_id || 'N/A'} | **OWASP**: ${f.owasp_category || 'N/A'}

### Description
${f.description}

### Location
- File: \`${f.file_path}\`
- Line: ${f.line_start}
- Detection: ${f.detection_method}

${f.attack_scenario ? `### Attack Scenario\n${f.attack_scenario}\n` : ''}
${f.proof_of_concept ? `### Proof of Concept\n\`\`\`\n${f.proof_of_concept}\n\`\`\`\n` : ''}
${f.ai_remediation ? `### Remediation\n${f.ai_remediation}\n` : ''}
${f.estimated_bounty ? `### Estimated Bounty: ${f.estimated_bounty}\n` : ''}
---`)
      setPreview(`# Security Report — ${scan?.name || 'Scan'}\n\n**Date**: ${format(new Date(), 'PPP')}\n**Total Findings**: ${filtered.length}\n\n${lines.join('\n')}`)
    } else if (format_ === 'executive') {
      const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
      filtered.forEach(f => { counts[f.severity] = (counts[f.severity] || 0) + 1 })
      setPreview(`# Executive Security Summary
## ${scan?.name || 'Application Security Review'}
**Date**: ${format(new Date(), 'PPP')} | **Risk Score**: ${scan?.risk_score}/100

## Key Findings

| Severity | Count | Business Impact |
|---|---|---|
| 🔴 Critical | ${counts.CRITICAL} | Immediate remediation required |
| 🟠 High | ${counts.HIGH} | Remediate within 7 days |
| 🟡 Medium | ${counts.MEDIUM} | Remediate within 30 days |
| 🟢 Low | ${counts.LOW} | Best-effort remediation |

## Risk Assessment
${counts.CRITICAL > 0 ? '⚠️ **CRITICAL RISK**: The application has critical vulnerabilities that must be addressed immediately before any production deployment.' : 'The application has manageable security risk. Prioritize remediation of HIGH severity issues.'}

## Top Recommendations
1. Implement parameterized queries to prevent SQL injection
2. Enable MFA for all administrative accounts
3. Rotate all exposed secrets and API keys immediately
4. Implement proper input validation and output encoding
5. Conduct regular automated security scans in CI/CD pipeline
`)
    } else if (format_ === 'sarif') {
      const sarif = {
        version: '2.1.0',
        runs: [{
          tool: { driver: { name: 'SecureReview AI', version: '1.0.0', rules: [] } },
          results: filtered.map(f => ({
            ruleId: f.cwe_id || 'UNKNOWN',
            message: { text: f.title },
            level: f.severity === 'CRITICAL' ? 'error' : f.severity === 'HIGH' ? 'warning' : 'note',
            locations: [{ physicalLocation: { artifactLocation: { uri: f.file_path }, region: { startLine: f.line_start } } }],
          })),
        }],
      }
      setPreview(JSON.stringify(sarif, null, 2))
    } else {
      const devReport = filtered.map(f =>
        `## ${f.title}\n**File**: ${f.file_path}:${f.line_start}\n**Fix**: ${f.ai_remediation || 'Apply security best practices'}\n${f.secure_code_example ? `**Secure Example**:\n\`\`\`\n${f.secure_code_example}\n\`\`\`` : ''}`
      ).join('\n\n---\n\n')
      setPreview(`# Developer Remediation Guide\n\n${devReport}`)
    }
  }

  function downloadReport() {
    if (!preview) return
    const ext = format_ === 'sarif' ? 'json' : 'md'
    const blob = new Blob([preview], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `securereview-${format_}-${Date.now()}.${ext}`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="page animate-in">
      <div className="page-header">
        <div>
          <h1 className="page-title">Reports</h1>
          <div className="page-subtitle">Generate professional security reports in multiple formats</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '320px 1fr', gap: 24 }}>
        {/* Config Panel */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Scan</div>
            <select className="input select" value={selectedScan || ''} onChange={e => setSelectedScan(e.target.value)}>
              {scans.map(s => <option key={s.id} value={s.id}>{s.name} ({s.total_findings} findings)</option>)}
              {scans.length === 0 && <option disabled>No completed scans</option>}
            </select>
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Report Format</div>
            {REPORT_FORMATS.map(f => (
              <div key={f.id}
                onClick={() => setFormat(f.id)}
                style={{
                  padding: '10px 12px', borderRadius: 'var(--radius-md)', cursor: 'pointer',
                  border: `1px solid ${format_ === f.id ? 'var(--accent)' : 'var(--border)'}`,
                  background: format_ === f.id ? 'var(--accent-glow)' : 'transparent',
                  marginBottom: 8, transition: 'var(--transition)',
                  display: 'flex', gap: 10, alignItems: 'flex-start',
                }}>
                <span style={{ fontSize: '1.1rem' }}>{f.emoji}</span>
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.875rem' }}>{f.label}</div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{f.desc}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="card">
            <div className="card-title" style={{ marginBottom: 12 }}>Filter Severity</div>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
              <label key={s} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8, cursor: 'pointer' }}>
                <input type="checkbox" checked={severityFilter.includes(s) || severityFilter.length === 0}
                  onChange={e => {
                    if (e.target.checked) setSeverityFilter(prev => prev.length === 0 ? [] : [...prev, s])
                    else setSeverityFilter(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s])
                  }} />
                <span className={`badge badge-${s.toLowerCase()}`}>{s}</span>
              </label>
            ))}
          </div>

          <button className="btn btn-primary" style={{ justifyContent: 'center' }} onClick={generateReport}>
            <Eye size={16} /> Preview Report
          </button>
          {preview && (
            <button className="btn btn-secondary" style={{ justifyContent: 'center' }} onClick={downloadReport}>
              <Download size={16} /> Download
            </button>
          )}
        </div>

        {/* Preview */}
        <div className="card" style={{ fontFamily: format_ === 'sarif' ? 'var(--font-mono)' : 'inherit' }}>
          <div className="card-header">
            <div className="card-title">Report Preview</div>
            {preview && <button className="btn btn-secondary btn-sm" onClick={downloadReport}><Download size={12} /> Download</button>}
          </div>
          {preview ? (
            <div style={{
              whiteSpace: 'pre-wrap',
              fontSize: '0.8rem',
              lineHeight: 1.8,
              color: 'var(--text-secondary)',
              maxHeight: '70vh',
              overflowY: 'auto',
              fontFamily: format_ === 'sarif' ? 'var(--font-mono)' : 'inherit',
            }}>
              {preview}
            </div>
          ) : (
            <div className="table-empty" style={{ padding: '80px 24px' }}>
              <FileText size={48} style={{ marginBottom: 16, opacity: 0.2 }} />
              <div>Select a scan and click "Preview Report"</div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
