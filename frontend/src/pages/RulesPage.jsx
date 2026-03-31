import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Shield, ChevronLeft, ChevronRight, Loader2 } from 'lucide-react'
import { getRulesJson, getRule } from '../api'
import { submitRule } from '../api'
import AnalyseModal from '../components/AnalyseModal'

export default function RulesPage() {
  const navigate = useNavigate()
  const [rules, setRules] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [ruleType, setRuleType] = useState('')
  const [severity, setSeverity] = useState('')
  const [source, setSource] = useState('')
  const [status, setStatus] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [analysing, setAnalysing] = useState(null)
  const [modalRule, setModalRule] = useState(null)

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await getRulesJson({ search, page, ruleType, severity, source, status })
      setRules(result.rules || [])
      setTotal(result.total || 0)
    } catch (e) {
      setError(e.message || 'Failed to load rules. Check Kibana settings.')
    }
    setLoading(false)
  }

  useEffect(() => { load() }, [page, ruleType, severity, source, status])

  const handleSearch = (e) => {
    e.preventDefault()
    setPage(1)
    load()
  }

  const openAnalyse = (rule) => {
    setModalRule(rule)
  }

  const confirmAnalyse = async ({ lookbackDays, indexOverride }) => {
    const ruleId = modalRule.id
    setModalRule(null)
    setAnalysing(ruleId)
    try {
      const ruleData = await getRule(ruleId)
      const content = JSON.stringify(ruleData, null, 2)
      const { analysis_id } = await submitRule(content, { formatHint: 'elastic', lookbackDays, indexOverride })
      navigate(`/report/${analysis_id}`)
    } catch (e) {
      setError(`Failed to analyse rule: ${e.message}`)
      setAnalysing(null)
    }
  }

  const totalPages = Math.ceil(total / 100)

  return (
    <>
    <div className="space-y-4">
      <header className="animate-in">
        <h1 className="text-2xl font-bold text-white">
          <span className="text-cyan-glow">Elastic</span> Detection Rules
        </h1>
        <p className="text-sm text-white/40 mt-0.5">Browse and analyse rules from Kibana</p>
      </header>

      {/* Search & Filters */}
      <div className="flex gap-2 flex-wrap animate-in" style={{ animationDelay: '0.05s' }}>
        <form onSubmit={handleSearch} className="flex-1 flex gap-2 min-w-[300px]">
          <div className="flex-1 relative">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-white/20" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search rules by name..."
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-white-5 border border-white-10 text-white text-sm placeholder:text-white/20 focus:outline-none focus:border-cyan-glow/40"
            />
          </div>
          <button type="submit" className="btn-ghost text-sm">Search</button>
        </form>
        <select value={ruleType} onChange={(e) => { setRuleType(e.target.value); setPage(1) }}
          className="px-3 py-2 rounded-xl bg-white-5 border border-white-10 text-white text-sm focus:outline-none cursor-pointer">
          <option value="">All Types</option>
          <option value="query">KQL / Lucene</option>
          <option value="eql">EQL</option>
          <option value="threshold">Threshold</option>
          <option value="esql">ES|QL</option>
          <option value="new_terms">New Terms</option>
          <option value="threat_match">Indicator Match</option>
          <option value="machine_learning">ML</option>
        </select>
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1) }}
          className="px-3 py-2 rounded-xl bg-white-5 border border-white-10 text-white text-sm focus:outline-none cursor-pointer">
          <option value="">All Severities</option>
          <option value="critical">🔴 Critical</option>
          <option value="high">🟠 High</option>
          <option value="medium">🟡 Medium</option>
          <option value="low">🔵 Low</option>
        </select>
        <select value={source} onChange={(e) => { setSource(e.target.value); setPage(1) }}
          className="px-3 py-2 rounded-xl bg-white-5 border border-white-10 text-white text-sm focus:outline-none cursor-pointer">
          <option value="">All Sources</option>
          <option value="elastic">Elastic</option>
          <option value="custom">Custom</option>
        </select>
        <select value={status} onChange={(e) => { setStatus(e.target.value); setPage(1) }}
          className="px-3 py-2 rounded-xl bg-white-5 border border-white-10 text-white text-sm focus:outline-none cursor-pointer">
          <option value="">All Status</option>
          <option value="enabled">✅ Enabled</option>
          <option value="disabled">⬚ Disabled</option>
        </select>
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">{error}</div>
      )}

      {/* Rules Table */}
      <div className="glass-card overflow-hidden animate-in" style={{ animationDelay: '0.1s' }}>
        {loading ? (
          <div className="flex items-center justify-center h-40">
            <div className="w-6 h-6 border-2 border-cyan-glow/30 border-t-cyan-glow rounded-full animate-spin" />
          </div>
        ) : rules.length === 0 ? (
          <div className="p-12 text-center">
            <Shield size={48} className="text-white/10 mx-auto mb-4" />
            <p className="text-white/30">No rules found. Check your Kibana URL and credentials in Settings.</p>
          </div>
        ) : (
          <>
            <div className="px-5 py-3 text-xs text-white/30 border-b border-white-8">{total} rules</div>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-white/30 text-xs uppercase tracking-wider border-b border-white-8">
                  <th className="text-left px-5 py-2 font-medium">Name</th>
                  <th className="text-left px-5 py-2 font-medium">Type</th>
                  <th className="text-left px-5 py-2 font-medium">Severity</th>
                  <th className="text-left px-5 py-2 font-medium">Source</th>
                  <th className="text-left px-5 py-2 font-medium">Status</th>
                  <th className="px-5 py-2 font-medium" />
                </tr>
              </thead>
              <tbody>
                {rules.map((r) => (
                  <tr key={r.id} className="border-b border-white-5 hover:bg-white-5 transition-colors">
                    <td className="px-5 py-3 text-white/80 font-medium max-w-[400px] truncate">{r.name}</td>
                    <td className="px-5 py-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-cyan-glow/10 text-cyan-glow border border-cyan-glow/20">
                        {r.type_label || r.type}
                      </span>
                    </td>
                    <td className="px-5 py-3"><SeverityBadge severity={r.severity} /></td>
                    <td className="px-5 py-3 text-white/40 text-xs">{r.immutable ? 'Elastic' : 'Custom'}</td>
                    <td className="px-5 py-3">
                      <span className={`text-xs font-medium ${r.enabled ? 'text-emerald-400' : 'text-white/20'}`}>
                        {r.enabled ? 'ON' : 'OFF'}
                      </span>
                    </td>
                    <td className="px-5 py-3">
                      <button
                        onClick={() => openAnalyse(r)}
                        disabled={analysing === r.id}
                        className="btn-glow-cyan text-xs px-3 py-1.5 disabled:opacity-50"
                      >
                        {analysing === r.id ? <Loader2 size={12} className="animate-spin" /> : 'Analyse'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {totalPages > 1 && (
              <div className="flex items-center justify-between px-5 py-3 border-t border-white-8">
                <span className="text-xs text-white/30">{total} rules</span>
                <div className="flex items-center gap-2">
                  <button disabled={page <= 1} onClick={() => setPage(page - 1)} className="p-1 text-white/30 hover:text-white/60 disabled:opacity-30 cursor-pointer"><ChevronLeft size={16} /></button>
                  <span className="text-xs text-white/50">Page {page} of {totalPages}</span>
                  <button disabled={page >= totalPages} onClick={() => setPage(page + 1)} className="p-1 text-white/30 hover:text-white/60 disabled:opacity-30 cursor-pointer"><ChevronRight size={16} /></button>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>

    {/* Analyse Modal */}
    {modalRule && (
      <AnalyseModal
        rule={modalRule}
        onConfirm={confirmAnalyse}
        onClose={() => setModalRule(null)}
      />
    )}
    </>
  )
}

function SeverityBadge({ severity }) {
  const styles = {
    critical: 'bg-red-500/15 text-red-400 border-red-500/30',
    high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  }
  return (
    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider border ${styles[severity] || 'bg-white/5 text-white/30 border-white/10'}`}>
      {severity || '—'}
    </span>
  )
}
