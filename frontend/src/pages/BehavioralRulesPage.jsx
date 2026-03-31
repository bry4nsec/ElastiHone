import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, ShieldAlert, Shield, ChevronLeft, ChevronRight, ChevronDown, Loader2 } from 'lucide-react'
import { getBehavioralRulesJson, getBehavioralRule, submitRule, getBehavioralTactics, getRulesJson, getRule, getAlertSubtypes } from '../api'
import AnalyseModal from '../components/AnalyseModal'

export default function BehavioralRulesPage() {
  const navigate = useNavigate()
  const [rules, setRules] = useState([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(1)
  const [search, setSearch] = useState('')
  const [platform, setPlatform] = useState('')
  const [tactic, setTactic] = useState('')
  const [tactics, setTactics] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [analysing, setAnalysing] = useState(null)
  const [modalRule, setModalRule] = useState(null)

  // Endpoint Protection envelope rules from Kibana
  const [endpointRules, setEndpointRules] = useState([])
  const [epLoading, setEpLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    setError(null)
    try {
      const result = await getBehavioralRulesJson({ search, platform, tactic, page })
      setRules(result.rules || [])
      setTotal(result.total || 0)
    } catch (e) {
      setError(e.message || 'Failed to load behavioral rules')
    }
    setLoading(false)
  }

  useEffect(() => {
    getBehavioralTactics().then((r) => setTactics(r.tactics || [])).catch(() => {})
    // Fetch the Endpoint Protection Kibana rules
    getRulesJson({ search: 'Elastic Defend', page: 1 })
      .then((r) => {
        const allRules = r.rules || []
        // Filter to only the endpoint protection envelope rules
        const epNames = [
          'endpoint security', 'behavior - detected', 'behavior - prevented',
          'malicious file - detected', 'malicious file - prevented',
          'memory threat - detected', 'memory threat - prevented',
          'ransomware - detected', 'ransomware - prevented',
        ]
        const filtered = allRules.filter(rule =>
          epNames.some(n => rule.name.toLowerCase().includes(n))
        )
        setEndpointRules(filtered)
      })
      .catch(() => {})
      .finally(() => setEpLoading(false))
  }, [])

  useEffect(() => { load() }, [page, platform, tactic])

  const handleSearch = (e) => {
    e.preventDefault()
    setPage(1)
    load()
  }

  const openAnalyse = (rule) => {
    setModalRule(rule)
  }

  const confirmAnalyse = async ({ lookbackDays, indexOverride }) => {
    const rule = modalRule
    setModalRule(null)
    const key = rule.path || rule.id
    setAnalysing(key)
    try {
      let ruleData
      if (rule.path) {
        // Behavioral rule from protections-artifacts
        ruleData = await getBehavioralRule(rule.path)
      } else {
        // Kibana detection rule (endpoint protection envelope)
        ruleData = await getRule(rule.id)
      }
      const content = JSON.stringify(ruleData, null, 2)
      const { analysis_id } = await submitRule(content, { formatHint: 'elastic', lookbackDays, indexOverride })
      navigate(`/report/${analysis_id}`)
    } catch (e) {
      setError(`Failed to analyse rule: ${e.message}`)
      setAnalysing(null)
    }
  }

  const totalPages = Math.ceil(total / 50)

  const platformIcons = { linux: '🐧', windows: '🪟', macos: '🍎', 'cross-platform': '🌐' }

  // Group endpoint rules by category
  const ruleCategories = [
    { key: 'behavioral', label: 'Behavioral Detection', icon: '🧠', color: 'violet', match: ['behavior -'] },
    { key: 'memory', label: 'Memory Threat', icon: '🔬', color: 'rose', match: ['memory threat'] },
    { key: 'malware', label: 'Malicious File', icon: '🦠', color: 'amber', match: ['malicious file'] },
    { key: 'ransomware', label: 'Ransomware', icon: '🔒', color: 'red', match: ['ransomware'] },
  ]

  const categorizeRules = () => {
    const grouped = {}
    let umbrella = null
    ruleCategories.forEach(c => { grouped[c.key] = [] })
    endpointRules.forEach(r => {
      const n = r.name.toLowerCase()
      if (n.includes('endpoint security')) { umbrella = r; return }
      for (const cat of ruleCategories) {
        if (cat.match.some(m => n.includes(m))) { grouped[cat.key].push(r); return }
      }
    })
    return { grouped, umbrella }
  }

  const { grouped, umbrella } = !epLoading ? categorizeRules() : { grouped: {}, umbrella: null }

  const catColors = {
    violet: 'border-violet-500/20 bg-violet-500/5',
    rose: 'border-rose-500/20 bg-rose-500/5',
    amber: 'border-amber-500/20 bg-amber-500/5',
    red: 'border-red-500/20 bg-red-500/5',
  }
  const catTextColors = {
    violet: 'text-violet-400',
    rose: 'text-rose-400',
    amber: 'text-amber-400',
    red: 'text-red-400',
  }

  return (
    <>
    <div className="space-y-4">
      <header className="animate-in">
        <h1 className="text-2xl font-bold text-white">
          <span className="text-violet-glow">Elastic Agent</span> Rules
        </h1>
        <p className="text-sm text-white/40 mt-0.5">
          Endpoint protection & behavioral rules from Elastic Defend
        </p>
      </header>

      {/* Endpoint Protection Rules — grouped by engine */}
      {epLoading ? (
        <div className="glass-card p-6 flex items-center justify-center animate-in" style={{ animationDelay: '0.05s' }}>
          <Loader2 size={16} className="animate-spin text-violet-glow/50 mr-2" />
          <span className="text-xs text-white/30">Loading endpoint protection rules from Kibana...</span>
        </div>
      ) : endpointRules.length > 0 ? (
        <div className="space-y-3 animate-in" style={{ animationDelay: '0.05s' }}>
          {/* Category cards */}
          {ruleCategories.map(cat => {
            const catRules = grouped[cat.key] || []
            if (catRules.length === 0) return null
            return (
              <div key={cat.key} className={`rounded-xl border p-3 ${catColors[cat.color]}`}>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-sm">{cat.icon}</span>
                  <h3 className={`text-xs font-semibold ${catTextColors[cat.color]}`}>{cat.label}</h3>
                  <span className="text-[9px] text-white/20 ml-auto">
                    {cat.key === 'behavioral' ? 'Public EQL rules' : 'Closed-source engine'} · Expand for alert subtypes
                  </span>
                </div>
                <div className="space-y-1">
                  {catRules.map(r => (
                    <EndpointRuleCard
                      key={r.id}
                      rule={r}
                      analysing={analysing}
                      onAnalyse={openAnalyse}
                      onAnalyseSubtype={(subtype) => {
                        setModalRule({ ...r, name: subtype.message, _subtypeOf: r.name })
                      }}
                    />
                  ))}
                </div>
              </div>
            )
          })}

          {/* Umbrella rule */}
          {umbrella && (
            <div className="rounded-xl border border-white-10 bg-white-5 p-3">
              <EndpointRuleCard
                rule={umbrella}
                analysing={analysing}
                onAnalyse={openAnalyse}
                onAnalyseSubtype={(subtype) => {
                  setModalRule({ ...umbrella, name: subtype.message, _subtypeOf: umbrella.name })
                }}
              />
            </div>
          )}
        </div>
      ) : null}

      {/* Divider */}
      <div className="flex items-center gap-3 pt-2 animate-in" style={{ animationDelay: '0.08s' }}>
        <div className="h-px flex-1 bg-gradient-to-r from-transparent via-violet-glow/20 to-transparent" />
        <div className="flex items-center gap-2">
          <ShieldAlert size={14} className="text-violet-glow/50" />
          <span className="text-[11px] font-semibold text-white/40 uppercase tracking-wider">Behavioral EQL Rules</span>
        </div>
        <div className="h-px flex-1 bg-gradient-to-r from-transparent via-violet-glow/20 to-transparent" />
      </div>
      <p className="text-[10px] text-white/20 text-center -mt-2">
        ~1,700+ public rules from{' '}
        <a href="https://github.com/elastic/protections-artifacts" target="_blank" rel="noopener noreferrer" className="text-violet-glow/40 hover:text-violet-glow underline">
          elastic/protections-artifacts
        </a>
      </p>

      {/* Filters */}
      <div className="flex gap-2 flex-wrap animate-in" style={{ animationDelay: '0.05s' }}>
        <form onSubmit={handleSearch} className="flex-1 flex gap-2 min-w-[300px]">
          <div className="flex-1 relative">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-white/20" />
            <input
              type="text" value={search} onChange={(e) => setSearch(e.target.value)}
              placeholder="Search behavioral rules..."
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-white-5 border border-white-10 text-white text-sm placeholder:text-white/20 focus:outline-none focus:border-cyan-glow/40"
            />
          </div>
          <button type="submit" className="btn-ghost text-sm">Search</button>
        </form>
        <select value={platform} onChange={(e) => { setPlatform(e.target.value); setPage(1) }}
          className="px-3 py-2 rounded-xl bg-white-5 border border-white-10 text-white text-sm focus:outline-none cursor-pointer">
          <option value="">All Platforms</option>
          <option value="windows">🪟 Windows</option>
          <option value="linux">🐧 Linux</option>
          <option value="macos">🍎 macOS</option>
          <option value="cross-platform">🌐 Cross-platform</option>
        </select>
        {tactics.length > 0 && (
          <select value={tactic} onChange={(e) => { setTactic(e.target.value); setPage(1) }}
            className="px-3 py-2 rounded-xl bg-white-5 border border-white-10 text-white text-sm focus:outline-none cursor-pointer">
            <option value="">All Tactics</option>
            {tactics.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        )}
      </div>

      {error && (
        <div className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">{error}</div>
      )}

      {/* Rules Table */}
      <div className="glass-card overflow-hidden animate-in" style={{ animationDelay: '0.1s' }}>
        {loading ? (
          <div className="flex items-center justify-center h-40">
            <div className="w-6 h-6 border-2 border-violet-glow/30 border-t-violet-glow rounded-full animate-spin" />
          </div>
        ) : rules.length === 0 ? (
          <div className="p-12 text-center">
            <ShieldAlert size={48} className="text-white/10 mx-auto mb-4" />
            <p className="text-white/30">No behavioral rules found</p>
          </div>
        ) : (
          <>
            <div className="px-5 py-3 text-xs text-white/30 border-b border-white-8">{total} Behavioral Protection rules</div>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-white/30 text-xs uppercase tracking-wider border-b border-white-8">
                  <th className="text-left px-5 py-2 font-medium">Name</th>
                  <th className="text-left px-5 py-2 font-medium">Type</th>
                  <th className="text-left px-5 py-2 font-medium">Severity</th>
                  <th className="text-left px-5 py-2 font-medium">Platform</th>
                  <th className="text-left px-5 py-2 font-medium">Tactic</th>
                  <th className="px-5 py-2" />
                </tr>
              </thead>
              <tbody>
                {rules.map((r, i) => (
                  <tr key={r.path || i} className="border-b border-white-5 hover:bg-white-5 transition-colors">
                    <td className="px-5 py-3 text-white/80 font-medium max-w-[350px] truncate">
                      {r.name}
                      {r.api_rule && <span className="ml-2 text-[9px] px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20" title="Uses API events">⚠ API</span>}
                      {r.ext_fields && !r.api_rule && <span className="ml-2 text-[9px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20" title="Uses Ext fields">⚡ Ext</span>}
                    </td>
                    <td className="px-5 py-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wider bg-violet-glow/10 text-violet-glow border border-violet-glow/20">EQL</span>
                    </td>
                    <td className="px-5 py-3"><SeverityBadge severity={r.severity || 'high'} /></td>
                    <td className="px-5 py-3 text-white/40 text-xs">{platformIcons[r.platform] || ''} {r.platform || ''}</td>
                    <td className="px-5 py-3 text-white/40 text-xs max-w-[150px] truncate">{(r.tactics || []).slice(0, 2).join(', ') || '—'}</td>
                    <td className="px-5 py-3">
                      <button
                        onClick={() => openAnalyse(r)}
                        disabled={analysing === r.path}
                        className="btn-glow-cyan text-xs px-3 py-1.5 disabled:opacity-50"
                      >
                        {analysing === r.path ? <Loader2 size={12} className="animate-spin" /> : 'Analyse'}
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

function EndpointRuleCard({ rule, analysing, onAnalyse, onAnalyseSubtype }) {
  const [expanded, setExpanded] = useState(false)
  const [subtypes, setSubtypes] = useState(null)
  const [loading, setLoading] = useState(false)

  const toggle = async () => {
    if (expanded) {
      setExpanded(false)
      return
    }
    setExpanded(true)
    if (!subtypes) {
      setLoading(true)
      try {
        const data = await getAlertSubtypes(rule.name, 7, rule.id)
        setSubtypes(data)
      } catch {
        setSubtypes({ subtypes: [], total: 0 })
      }
      setLoading(false)
    }
  }

  return (
    <div className="rounded-lg border border-white-8 overflow-hidden transition-colors hover:border-violet-glow/20">
      {/* Header */}
      <div
        className="flex items-center gap-2 px-3 py-2 bg-white-5 cursor-pointer select-none"
        onClick={toggle}
      >
        <ChevronDown size={14} className={`text-white/30 transition-transform ${expanded ? 'rotate-0' : '-rotate-90'}`} />
        <div className="min-w-0 flex-1">
          <div className="text-xs text-white/80 font-medium truncate">{rule.name}</div>
          <div className="flex items-center gap-2 mt-0.5">
            <span className={`text-[9px] font-medium ${rule.enabled ? 'text-emerald-400' : 'text-white/20'}`}>
              {rule.enabled ? '● ON' : '○ OFF'}
            </span>
            <span className="text-[9px] text-white/20">|</span>
            <SeverityBadge severity={rule.severity} />
            {subtypes && <span className="text-[9px] text-white/20">| {subtypes.total} alerts · {subtypes.subtypes?.length || 0} subtypes</span>}
          </div>
        </div>
        <button
          onClick={(e) => { e.stopPropagation(); onAnalyse(rule) }}
          disabled={analysing === rule.id}
          className="btn-glow-cyan text-[10px] px-2 py-1 disabled:opacity-50 shrink-0"
        >
          {analysing === rule.id ? <Loader2 size={10} className="animate-spin" /> : 'Analyse All'}
        </button>
      </div>

      {/* Subtypes panel */}
      {expanded && (
        <div className="border-t border-white-5 bg-[#0a0a14]">
          {loading ? (
            <div className="flex items-center justify-center py-6">
              <Loader2 size={16} className="animate-spin text-violet-glow/50" />
              <span className="ml-2 text-xs text-white/30">Fetching alert subtypes...</span>
            </div>
          ) : subtypes?.subtypes?.length > 0 ? (
            <div className="max-h-[300px] overflow-y-auto">
              {subtypes.subtypes.map((st, i) => (
                <div key={i} className="flex items-center justify-between gap-2 px-4 py-1.5 border-b border-white-5 last:border-0 hover:bg-white-5 transition-colors">
                  <div className="flex-1 min-w-0">
                    <span className="text-[11px] text-white/70 truncate block">{st.message}</span>
                  </div>
                  <span className="text-[10px] text-white/30 font-mono shrink-0 w-16 text-right">{st.count.toLocaleString()}</span>
                  <button
                    onClick={() => onAnalyseSubtype(st)}
                    className="text-[10px] px-2 py-0.5 rounded-md bg-violet-glow/10 text-violet-glow border border-violet-glow/20 hover:bg-violet-glow/20 transition-colors shrink-0"
                  >
                    Analyse
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <div className="py-4 text-center text-xs text-white/20">
              No alerts found for this rule in the last 7 days
            </div>
          )}
        </div>
      )}
    </div>
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
      {severity}
    </span>
  )
}
