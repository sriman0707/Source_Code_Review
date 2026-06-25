import React, { useState, useEffect } from 'react'
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, LineChart, Line, Legend, AreaChart, Area,
} from 'recharts'
import {
  ShieldAlert, AlertTriangle, AlertCircle, Info,
  TrendingUp, Scan, Clock, Zap, Target
} from 'lucide-react'
import { dashboardAPI } from '../api/client'
import { format } from 'date-fns'

const SEVERITY_COLORS = {
  CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e', INFO: '#94a3b8'
}

function MetricCard({ label, value, icon: Icon, type, sub }) {
  return (
    <div className={`metric-card ${type}`}>
      <div className={`metric-icon`}><Icon size={20} /></div>
      <div className="metric-value" style={{ color: `var(--${type === 'accent' ? 'accent' : type})` }}>{value}</div>
      <div className="metric-label">{label}</div>
      {sub && <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: 4 }}>{sub}</div>}
    </div>
  )
}

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 8, padding: '10px 14px', fontSize: '0.8rem' }}>
      <div style={{ color: 'var(--text-muted)', marginBottom: 6 }}>{label}</div>
      {payload.map(p => (
        <div key={p.name} style={{ color: p.color }}>{p.name}: <strong>{p.value}</strong></div>
      ))}
    </div>
  )
}

export default function Dashboard() {
  const [summary, setSummary] = useState(null)
  const [trends, setTrends] = useState([])
  const [topFindings, setTopFindings] = useState([])
  const [cweData, setCweData] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    async function load() {
      try {
        const [sumRes, trendRes, topRes, cweRes] = await Promise.all([
          dashboardAPI.summary(),
          dashboardAPI.trends(30),
          dashboardAPI.topFindings(8),
          dashboardAPI.cweBreakdown(),
        ])
        setSummary(sumRes.data)
        setTrends(trendRes.data.trends || [])
        setTopFindings(topRes.data.findings || [])
        setCweData(cweRes.data.cwe_breakdown || [])
      } catch (e) {
        console.error('Dashboard load error:', e)
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  if (loading) return (
    <div className="page" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '60vh' }}>
      <div style={{ textAlign: 'center' }}>
        <div className="spinner" style={{ width: 40, height: 40, margin: '0 auto 16px' }} />
        <div style={{ color: 'var(--text-muted)' }}>Loading security data...</div>
      </div>
    </div>
  )

  const sev = summary?.severity_distribution || {}
  const pieData = Object.entries(sev)
    .filter(([, v]) => v > 0)
    .map(([name, value]) => ({ name, value }))

  const owaspData = Object.entries(summary?.owasp_breakdown || {}).map(([name, count]) => ({ name, count }))

  return (
    <div className="page animate-in">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Security Dashboard</h1>
          <div className="page-subtitle">Real-time vulnerability intelligence across all your scans</div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', background: 'var(--bg-card)', padding: '6px 12px', borderRadius: 'var(--radius-md)', border: '1px solid var(--border)' }}>
            Risk Score: <span style={{ color: summary?.risk_score > 70 ? 'var(--critical)' : summary?.risk_score > 40 ? 'var(--medium)' : 'var(--low)', fontWeight: 700 }}>
              {summary?.risk_score ?? 0}/100
            </span>
          </div>
        </div>
      </div>

      {/* Metric Cards */}
      <div className="metric-grid">
        <MetricCard label="Critical Findings" value={sev.CRITICAL || 0} icon={ShieldAlert} type="critical" />
        <MetricCard label="High Severity" value={sev.HIGH || 0} icon={AlertTriangle} type="high" />
        <MetricCard label="Medium Severity" value={sev.MEDIUM || 0} icon={AlertCircle} type="medium" />
        <MetricCard label="Low / Info" value={(sev.LOW || 0) + (sev.INFO || 0)} icon={Info} type="low" />
        <MetricCard label="Total Scans" value={summary?.total_scans || 0} icon={Scan} type="accent" sub={`${summary?.active_scans || 0} active`} />
      </div>

      {/* Charts Row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 24 }}>
        {/* Severity Pie */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Severity Distribution</div>
          </div>
          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={3} dataKey="value">
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name]} />
                  ))}
                </Pie>
                <Tooltip content={<CustomTooltip />} />
                <Legend
                  formatter={(value) => <span style={{ color: 'var(--text-secondary)', fontSize: '0.8rem' }}>{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="table-empty">No findings yet. Run your first scan!</div>
          )}
        </div>

        {/* OWASP Breakdown */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">OWASP Top 10 Mapping</div>
          </div>
          {owaspData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={owaspData} layout="vertical" margin={{ left: 20, right: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} />
                <YAxis type="category" dataKey="name" width={90} tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="count" fill="var(--accent)" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="table-empty">No data yet</div>
          )}
        </div>
      </div>

      {/* Trends Chart */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-header">
          <div className="card-title">Finding Trends (30 days)</div>
          <TrendingUp size={16} color="var(--accent)" />
        </div>
        {trends.length > 0 ? (
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={trends}>
              <defs>
                {Object.entries(SEVERITY_COLORS).map(([key, color]) => (
                  <linearGradient key={key} id={`grad-${key}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor={color} stopOpacity={0.3} />
                    <stop offset="95%" stopColor={color} stopOpacity={0} />
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
              <XAxis dataKey="date" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
              <Tooltip content={<CustomTooltip />} />
              <Legend />
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
                <Area key={sev} type="monotone" dataKey={sev} stroke={SEVERITY_COLORS[sev]}
                  fill={`url(#grad-${sev})`} strokeWidth={2} dot={false} />
              ))}
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div className="table-empty">Run scans to see trend data</div>
        )}
      </div>

      {/* Top Findings Table */}
      <div className="card">
        <div className="card-header">
          <div className="card-title">Top Critical Findings</div>
          <Target size={16} color="var(--critical)" />
        </div>
        {topFindings.length > 0 ? (
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Title</th>
                  <th>File</th>
                  <th>CWE</th>
                  <th>CVSS</th>
                  <th>Scan</th>
                </tr>
              </thead>
              <tbody>
                {topFindings.map(f => (
                  <tr key={f.id}>
                    <td><span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                    <td style={{ maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                      {f.file_path.split('/').pop()}:{f.line_start}
                    </td>
                    <td><span style={{ color: 'var(--accent)', fontSize: '0.8rem' }}>{f.cwe_id}</span></td>
                    <td>
                      {f.cvss_score ? (
                        <span style={{ color: f.cvss_score >= 9 ? 'var(--critical)' : f.cvss_score >= 7 ? 'var(--high)' : 'var(--medium)', fontWeight: 700 }}>
                          {f.cvss_score.toFixed(1)}
                        </span>
                      ) : '—'}
                    </td>
                    <td style={{ color: 'var(--text-muted)', fontSize: '0.8rem' }}>{f.scan_name}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="table-empty">
            <ShieldAlert size={32} style={{ marginBottom: 12, opacity: 0.3 }} />
            <div>No findings yet. Upload code to scan!</div>
          </div>
        )}
      </div>
    </div>
  )
}
