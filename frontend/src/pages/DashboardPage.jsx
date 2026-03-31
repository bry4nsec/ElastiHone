import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  ShieldCheck, AlertTriangle, Clock, CheckCircle, XCircle,
  Eye, Activity, Wrench, Zap, Filter, TrendingDown, Brain,
  ShieldOff, Shield,
} from 'lucide-react'
import MetricCard from '../components/MetricCard'
import { getMetrics, getHealth, getCoverage } from '../api'

export default function DashboardPage() {
  const navigate = useNavigate()
  const [metrics, setMetrics] = useState(null)
  const [health, setHealth] = useState(null)
  const [coverage, setCoverage] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([getMetrics(), getHealth(), getCoverage().catch(() => null)])
      .then(([m, h, c]) => { setMetrics(m); setHealth(h); setCoverage(c) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="w-8 h-8 border-2 border-cyan-glow/30 border-t-cyan-glow rounded-full animate-spin" />
      </div>
    )
  }

  const v = metrics?.verdicts || {}
  const sev = metrics?.severities || {}
  const totalAnalyses = metrics?.total_analyses || 0
  const alertsPerDay = metrics?.total_alerts_per_day || 0
  const avgFpr = metrics?.avg_fpr || 0
  const totalTokens = metrics?.total_ai_tokens || 0
  const exceptionsApplied = metrics?.exceptions_applied || 0

  const cov = coverage?.totals || {}
  const covBySev = coverage?.by_severity || {}
  const coveragePct = coverage?.coverage_pct || 0

  return (
    <div className="space-y-6">
      <header className="flex items-center justify-between animate-in">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Elasti<span className="text-cyan-glow">Hone</span> Dashboard
          </h1>
          <p className="text-sm text-white/40 mt-0.5">
            Detection rule performance overview
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white-5 border border-white-10 text-xs text-white/60">
            <Activity size={14} className="text-cyan-glow" />
            <span>{health?.status === 'ok' ? 'Backend Connected' : 'Disconnected'}</span>
            <span className={`w-2 h-2 rounded-full ${health?.status === 'ok' ? 'bg-emerald-400' : 'bg-red-400'}`} />
          </div>
          <button
            onClick={() => navigate('/rules')}
            className="btn-glow-cyan text-sm"
          >
            Browse Rules
          </button>
        </div>
      </header>

      {/* ── Rule Coverage Gap ── */}
      {coverage && cov.total > 0 && (
        <div className="space-y-4">
          <div className="grid grid-cols-3 gap-4">
            {/* Coverage Overview */}
            <div className="glass-card p-5 animate-in" style={{ animationDelay: '0.03s' }}>
              <div className="flex items-center gap-3 mb-4">
                <div className="w-9 h-9 rounded-lg flex items-center justify-center" style={{ background: 'rgba(0,229,255,0.08)' }}>
                  <Shield size={18} className="text-cyan-glow" />
                </div>
                <div>
                  <h3 className="text-sm font-semibold text-white">Rule Coverage</h3>
                  <p className="text-[10px] text-white/30 uppercase tracking-wider">{cov.total} total rules</p>
                </div>
              </div>
              <div className="flex items-end gap-4 mb-3">
                <div>
                  <span className="text-3xl font-bold text-white">{coveragePct}</span>
                  <span className="text-lg text-white/30">%</span>
                </div>
                <div className="flex-1 flex items-center gap-3 pb-1">
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-sm bg-emerald-400" />
                    <span className="text-xs text-white/50">{cov.enabled} enabled</span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="w-2.5 h-2.5 rounded-sm bg-red-400/50" />
                    <span className="text-xs text-white/50">{cov.disabled} disabled</span>
                  </div>
                </div>
              </div>
              <div className="h-3 rounded-full bg-white/5 overflow-hidden">
                <div
                  className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-emerald-400 transition-all duration-700"
                  style={{ width: `${coveragePct}%` }}
                />
              </div>
            </div>

            {/* Coverage by Severity */}
            <div className="glass-card p-5 col-span-2 animate-in" style={{ animationDelay: '0.06s' }}>
              <h3 className="text-sm font-semibold text-white mb-4">Coverage by Severity</h3>
              <div className="grid grid-cols-4 gap-4">
                {[
                  { key: 'critical', label: 'Critical', barEnabled: 'from-red-600 to-red-400', textColor: 'text-red-400' },
                  { key: 'high', label: 'High', barEnabled: 'from-orange-600 to-orange-400', textColor: 'text-orange-400' },
                  { key: 'medium', label: 'Medium', barEnabled: 'from-amber-600 to-amber-400', textColor: 'text-amber-400' },
                  { key: 'low', label: 'Low', barEnabled: 'from-emerald-600 to-emerald-400', textColor: 'text-emerald-400' },
                ].map((item) => {
                  const sevData = covBySev[item.key] || {}
                  const en = sevData.enabled || 0
                  const dis = sevData.disabled || 0
                  const total = en + dis
                  const pct = total > 0 ? Math.round((en / total) * 100) : 0
                  return (
                    <div key={item.key} className="text-center">
                      <span className={`text-xs font-semibold uppercase tracking-wider ${item.textColor}`}>{item.label}</span>
                      <div className="mt-2 mb-1">
                        <span className="text-2xl font-bold text-white">{en}</span>
                        <span className="text-white/20 text-sm">/{total}</span>
                      </div>
                      <div className="h-2 rounded-full bg-white/5 overflow-hidden mb-1">
                        <div
                          className={`h-full rounded-full bg-gradient-to-r ${item.barEnabled} transition-all duration-500`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                      <span className="text-[10px] text-white/30">{pct}% enabled</span>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>

          {/* Deprecated + No Integrations alerts */}
          {((coverage.deprecated?.count > 0) || (coverage.no_integrations?.count > 0)) && (
            <div className="grid grid-cols-2 gap-4">
              {/* Deprecated Rules */}
              {coverage.deprecated?.count > 0 && (
                <div className="glass-card p-5 border-amber-500/20 animate-in" style={{ animationDelay: '0.08s' }}>
                  <div className="flex items-center gap-3 mb-3">
                    <div className="w-8 h-8 rounded-lg flex items-center justify-center bg-amber-500/10">
                      <AlertTriangle size={16} className="text-amber-400" />
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-amber-400">Deprecated Rules</h3>
                      <p className="text-[10px] text-white/30">{coverage.deprecated.count} rules marked as deprecated</p>
                    </div>
                  </div>
                  <details className="cursor-pointer">
                    <summary className="text-[10px] text-white/30 uppercase tracking-wider hover:text-white/50 transition-colors">
                      Show {coverage.deprecated.count} deprecated rules
                    </summary>
                    <div className="mt-2 max-h-48 overflow-y-auto space-y-1">
                      {coverage.deprecated.rules.map((r, i) => (
                        <div key={i} className="flex items-center justify-between py-1.5 px-2 rounded-lg bg-white/3 text-xs">
                          <span className="text-white/60 truncate max-w-[70%]">{r.name}</span>
                          <div className="flex items-center gap-2">
                            <SeverityBadge severity={r.severity} />
                            <span className={`text-[9px] font-medium ${r.enabled ? 'text-emerald-400' : 'text-white/20'}`}>
                              {r.enabled ? 'ON' : 'OFF'}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </details>
                </div>
              )}

              {/* No Integrations */}
              {coverage.no_integrations?.count > 0 && (
                <div className="glass-card p-5 border-red-500/20 animate-in" style={{ animationDelay: '0.1s' }}>
                  <div className="flex items-center gap-3 mb-3">
                    <div className="w-8 h-8 rounded-lg flex items-center justify-center bg-red-500/10">
                      <ShieldOff size={16} className="text-red-400" />
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-red-400">No Integrations</h3>
                      <p className="text-[10px] text-white/30">{coverage.no_integrations.count} Elastic rules without integrations</p>
                    </div>
                  </div>
                  <details className="cursor-pointer">
                    <summary className="text-[10px] text-white/30 uppercase tracking-wider hover:text-white/50 transition-colors">
                      Show {coverage.no_integrations.count} rules without integrations
                    </summary>
                    <div className="mt-2 max-h-48 overflow-y-auto space-y-1">
                      {coverage.no_integrations.rules.map((r, i) => (
                        <div key={i} className="flex items-center justify-between py-1.5 px-2 rounded-lg bg-white/3 text-xs">
                          <span className="text-white/60 truncate max-w-[70%]">{r.name}</span>
                          <div className="flex items-center gap-2">
                            <SeverityBadge severity={r.severity} />
                            <span className={`text-[9px] font-medium ${r.enabled ? 'text-emerald-400' : 'text-white/20'}`}>
                              {r.enabled ? 'ON' : 'OFF'}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </details>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Primary Verdict Metrics ── */}
      <div className="grid grid-cols-5 gap-4">
        <div className="animate-in" style={{ animationDelay: '0.1s' }}>
          <MetricCard title="Total Analyses" value={totalAnalyses} icon={<ShieldCheck size={18} />} accent="cyan" />
        </div>
        <div className="animate-in" style={{ animationDelay: '0.12s' }}>
          <MetricCard title="Approved" value={v.approve || 0} positive icon={<CheckCircle size={18} />} accent="lime" />
        </div>
        <div className="animate-in" style={{ animationDelay: '0.14s' }}>
          <MetricCard title="Tunable" value={v.tune || 0} icon={<Wrench size={18} />} accent="cyan" />
        </div>
        <div className="animate-in" style={{ animationDelay: '0.16s' }}>
          <MetricCard title="Needs Review" value={v.review || 0} icon={<Eye size={18} />} accent="violet" />
        </div>
        <div className="animate-in" style={{ animationDelay: '0.18s' }}>
          <MetricCard title="Rejected" value={v.reject || 0} icon={<XCircle size={18} />} accent="red" />
        </div>
      </div>

      {/* ── Operational KPIs ── */}
      <div className="grid grid-cols-4 gap-4">
        <div className="animate-in" style={{ animationDelay: '0.2s' }}>
          <MetricCard title="Alerts/Day" value={alertsPerDay.toFixed(1)} icon={<AlertTriangle size={18} />} accent="cyan" />
        </div>
        <div className="animate-in" style={{ animationDelay: '0.22s' }}>
          <MetricCard title="Avg FPR" value={`${(avgFpr * 100).toFixed(2)}%`} icon={<TrendingDown size={18} />} accent="lime" />
        </div>
        <div className="animate-in" style={{ animationDelay: '0.24s' }}>
          <MetricCard title="Exceptions Applied" value={exceptionsApplied} icon={<Filter size={18} />} accent="violet" />
        </div>
        <div className="animate-in" style={{ animationDelay: '0.26s' }}>
          <MetricCard title="AI Tokens Used" value={totalTokens > 1000 ? `${(totalTokens/1000).toFixed(0)}k` : totalTokens} icon={<Brain size={18} />} accent="cyan" />
        </div>
      </div>

      {/* ── Verdict Distribution + Severity Breakdown ── */}
      <div className="grid grid-cols-2 gap-4">
        <div className="glass-card p-5 animate-in" style={{ animationDelay: '0.28s' }}>
          <h3 className="text-sm font-semibold text-white mb-4">Verdict Distribution</h3>
          <div className="flex items-end gap-3 h-32">
            {[
              { key: 'approve', label: 'Approve', color: 'bg-emerald-400', count: v.approve || 0 },
              { key: 'tune', label: 'Tune', color: 'bg-cyan-glow', count: v.tune || 0 },
              { key: 'review', label: 'Review', color: 'bg-amber-400', count: v.review || 0 },
              { key: 'reject', label: 'Reject', color: 'bg-red-400', count: v.reject || 0 },
              { key: 'error', label: 'Error', color: 'bg-white/20', count: v.error || 0 },
            ].map((item) => {
              const max = Math.max(v.approve || 0, v.tune || 0, v.review || 0, v.reject || 0, v.error || 0, 1)
              const pct = (item.count / max) * 100
              return (
                <div key={item.key} className="flex-1 flex flex-col items-center gap-2">
                  <span className="text-xs text-white/60 font-bold">{item.count}</span>
                  <div className="w-full rounded-t-lg relative" style={{ height: `${Math.max(pct, 4)}%` }}>
                    <div className={`absolute inset-0 rounded-t-lg ${item.color} opacity-80`} />
                  </div>
                  <span className="text-[10px] text-white/30 uppercase tracking-wider">{item.label}</span>
                </div>
              )
            })}
          </div>
        </div>

        <div className="glass-card p-5 animate-in" style={{ animationDelay: '0.3s' }}>
          <h3 className="text-sm font-semibold text-white mb-4">Analysis by Severity</h3>
          <div className="space-y-3">
            {[
              { key: 'critical', label: 'Critical', color: 'bg-red-500', textColor: 'text-red-400', count: sev.critical || 0 },
              { key: 'high', label: 'High', color: 'bg-orange-500', textColor: 'text-orange-400', count: sev.high || 0 },
              { key: 'medium', label: 'Medium', color: 'bg-amber-500', textColor: 'text-amber-400', count: sev.medium || 0 },
              { key: 'low', label: 'Low', color: 'bg-emerald-500', textColor: 'text-emerald-400', count: sev.low || 0 },
            ].map((item) => {
              const total = (sev.critical || 0) + (sev.high || 0) + (sev.medium || 0) + (sev.low || 0)
              const pct = total > 0 ? (item.count / total) * 100 : 0
              return (
                <div key={item.key} className="flex items-center gap-3">
                  <span className={`text-xs font-medium w-16 ${item.textColor}`}>{item.label}</span>
                  <div className="flex-1 h-2 rounded-full bg-white/5 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${item.color} opacity-60 transition-all duration-500`}
                      style={{ width: `${Math.max(pct, 0)}%` }}
                    />
                  </div>
                  <span className="text-xs text-white/40 w-12 text-right font-mono">{item.count}</span>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* ── Rule Performance Table ── */}
      {metrics?.rule_summaries?.length > 0 && (
        <div className="glass-card p-5 animate-in" style={{ animationDelay: '0.35s' }}>
          <h3 className="text-sm font-semibold text-white mb-4">Rule Performance</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-white/30 text-xs uppercase tracking-wider border-b border-white-8">
                  <th className="text-left py-2 font-medium">Rule Name</th>
                  <th className="text-left py-2 font-medium">Type</th>
                  <th className="text-left py-2 font-medium">Severity</th>
                  <th className="text-left py-2 font-medium">Verdict</th>
                  <th className="text-right py-2 font-medium">Alerts</th>
                  <th className="text-right py-2 font-medium">Alerts/Day</th>
                  <th className="text-right py-2 font-medium">FPR</th>
                  <th className="text-right py-2 font-medium">Runs</th>
                </tr>
              </thead>
              <tbody>
                {metrics.rule_summaries.map((rule) => (
                  <tr
                    key={rule.latest_id}
                    onClick={() => navigate(`/report/${rule.latest_id}`)}
                    className="border-b border-white-5 hover:bg-white-5 cursor-pointer transition-colors"
                  >
                    <td className="py-3 text-white/80 font-medium max-w-[250px] truncate">{rule.name}</td>
                    <td className="py-3 text-white/40 font-mono text-xs">{rule.rule_type || '—'}</td>
                    <td className="py-3"><SeverityBadge severity={rule.severity} /></td>
                    <td className="py-3"><VerdictBadge verdict={rule.latest_verdict} /></td>
                    <td className="py-3 text-right text-white/60">{rule.latest_alerts ?? '—'}</td>
                    <td className="py-3 text-right text-white/60">{(rule.latest_apd || 0).toFixed(1)}</td>
                    <td className="py-3 text-right text-white/60 font-mono text-xs">
                      {((rule.latest_fpr || 0) * 100).toFixed(2)}%
                    </td>
                    <td className="py-3 text-right text-white/40">{rule.analyses_count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {totalAnalyses === 0 && (
        <div className="glass-card p-12 text-center animate-in" style={{ animationDelay: '0.25s' }}>
          <ShieldCheck size={48} className="text-white/10 mx-auto mb-4" />
          <p className="text-white/40 mb-4">No analyses yet. Submit a rule to get started.</p>
          <button onClick={() => navigate('/rules')} className="btn-glow-cyan">
            Browse Elastic Rules
          </button>
        </div>
      )}
    </div>
  )
}

function VerdictBadge({ verdict }) {
  const styles = {
    approve: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    review: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    tune: 'bg-cyan-glow/10 text-cyan-glow border-cyan-glow/30',
    reject: 'bg-red-500/15 text-red-400 border-red-500/30',
    error: 'bg-white/5 text-white/30 border-white/10',
  }
  return (
    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider border ${styles[verdict] || styles.error}`}>
      {verdict || '—'}
    </span>
  )
}

function SeverityBadge({ severity }) {
  const s = (severity || '').toLowerCase()
  const styles = {
    critical: 'text-red-400',
    high: 'text-orange-400',
    medium: 'text-amber-400',
    low: 'text-emerald-400',
  }
  return (
    <span className={`text-xs font-medium ${styles[s] || 'text-white/30'}`}>
      {severity || '—'}
    </span>
  )
}
