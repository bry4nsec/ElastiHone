import { useState, useEffect } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, CheckCircle, XCircle, Eye, AlertTriangle, Clock, Loader2, Cpu, Zap, Wrench } from 'lucide-react'
import { waitForAnalysis, getAnalysis } from '../api'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

export default function ReportPage() {
  const { analysisId } = useParams()
  const navigate = useNavigate()
  const [report, setReport] = useState(null)
  const [status, setStatus] = useState('loading')

  useEffect(() => {
    // First try to get existing report
    getAnalysis(analysisId).then((data) => {
      if (data && data.status === 'done') {
        setReport(data)
        setStatus('done')
      } else {
        // Poll until done
        setStatus('running')
        waitForAnalysis(analysisId, (s) => setStatus(s)).then((r) => {
          setReport(r)
          setStatus('done')
        })
      }
    })
  }, [analysisId])

  if (status === 'loading' || status === 'running') {
    return (
      <div className="flex flex-col items-center justify-center h-96 gap-4 animate-in">
        <div className="w-12 h-12 border-2 border-cyan-glow/30 border-t-cyan-glow rounded-full animate-spin" />
        <p className="text-white/40 text-sm">Analysing rule — investigating noise patterns...</p>
        <p className="text-white/20 text-xs">{analysisId}</p>
      </div>
    )
  }

  if (!report) {
    return (
      <div className="flex flex-col items-center justify-center h-96 gap-4">
        <XCircle size={48} className="text-red-400/30" />
        <p className="text-white/40">Analysis not found</p>
        <button onClick={() => navigate('/')} className="btn-ghost text-sm">Back to Dashboard</button>
      </div>
    )
  }

  const verdict = report.verdict || 'error'
  const hasError = report.error

  return (
    <div className="space-y-4">
      <header className="flex items-center gap-4 animate-in">
        <button onClick={() => navigate('/')} className="text-white/30 hover:text-white/60 transition-colors cursor-pointer">
          <ArrowLeft size={20} />
        </button>
        <div className="flex-1">
          <h1 className="text-xl font-bold text-white">{report.rule_name || 'Unknown Rule'}</h1>
          <p className="text-xs text-white/30 font-mono">{analysisId}</p>
        </div>
        <VerdictBadgeLarge verdict={verdict} />
      </header>

      {hasError && (
        <div className="glass-card p-5 border-red-500/20 animate-in" style={{ animationDelay: '0.05s' }}>
          <h3 className="text-sm font-semibold text-red-400 mb-2">Error</h3>
          <pre className="text-xs text-white/60 whitespace-pre-wrap font-mono">{report.error}</pre>
        </div>
      )}

      {/* Metrics Grid */}
      <div className="grid grid-cols-4 gap-4 animate-in" style={{ animationDelay: '0.1s' }}>
        <StatCard label="Noise Hits" value={report.noise_hits ?? '—'} icon={<AlertTriangle size={16} />} />
        <StatCard label="Production Alerts" value={report.actual_alert_count === -1 ? 'N/A' : report.actual_alert_count} icon={<Eye size={16} />} />
        <StatCard label="Alerts/Day" value={(report.estimated_alerts_per_day || 0).toFixed(1)} icon={<Clock size={16} />} />
        <StatCard label="FPR" value={`${((report.fpr || 0) * 100).toFixed(3)}%`} icon={<XCircle size={16} />} />
      </div>

      {/* Rule Details */}
      <div className="grid grid-cols-2 gap-4">
        <div className="glass-card p-5 animate-in" style={{ animationDelay: '0.15s' }}>
          <h3 className="text-sm font-semibold text-white mb-3">Rule Details</h3>
          <div className="space-y-2 text-sm">
            <Row label="Type" value={report.rule_type || '—'} />
            <Row label="Severity" value={report.severity || '—'} />
            <Row label="Indices" value={(report.target_indices || []).join(', ') || '—'} />
            <Row label="MITRE" value={(report.mitre_techniques || []).join(', ') || '—'} />
            <Row label="Duration" value={`${(report.analysis_duration_seconds || 0).toFixed(1)}s`} />
            <Row label="AI Tokens" value={report.ai_tokens_used || 0} />
          </div>
        </div>

        {/* Verdict Reason */}
        <div className="glass-card p-5 animate-in" style={{ animationDelay: '0.2s' }}>
          <h3 className="text-sm font-semibold text-white mb-3">Verdict Reason</h3>
          <p className="text-sm text-white/60">{report.verdict_reason || 'No specific reason provided'}</p>

          {report.suppression_fields?.length > 0 && (
            <div className="mt-4 text-xs text-white/40">
              <span className="text-white/20">Suppression:</span> {report.suppression_fields.join(' + ')} ({report.suppression_duration || 'N/A'})
            </div>
          )}
        </div>
      </div>

      {/* AI Recommendations */}
      {report.recommendations?.length > 0 && (
        <div className="glass-card p-5 animate-in" style={{ animationDelay: '0.25s' }}>
          <h3 className="text-sm font-semibold text-white mb-4">AI Recommendations</h3>
          <div className="space-y-4">
            {report.recommendations.map((rec, i) => (
              <div key={i} className="p-5 rounded-xl bg-white-5 border border-white-8 prose-report">
                <Markdown remarkPlugins={[remarkGfm]}>{rec}</Markdown>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Exclusion Queries — parsed from recommendations */}
      <ExclusionSection report={report} analysisId={analysisId} />

      {/* Cost Analysis */}
      {report.cost_analysis && (
        <div className="glass-card p-5 animate-in" style={{ animationDelay: '0.3s' }}>
          <h3 className="text-sm font-semibold text-white mb-3">Cost Analysis</h3>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-3 rounded-lg bg-white-5">
              <div className="flex items-center gap-1.5 text-white/30 mb-1"><Cpu size={12} /><span className="text-[10px] uppercase tracking-wider">Level</span></div>
              <CostLevelBadge level={report.cost_analysis.level} />
            </div>
            <div className="p-3 rounded-lg bg-white-5">
              <div className="flex items-center gap-1.5 text-white/30 mb-1"><Zap size={12} /><span className="text-[10px] uppercase tracking-wider">Complexity</span></div>
              <div className="text-lg font-bold text-white">{report.cost_analysis.query_complexity_score ?? 0}<span className="text-xs text-white/30 font-normal">/100</span></div>
            </div>
            <div className="p-3 rounded-lg bg-white-5">
              <div className="text-[10px] uppercase tracking-wider text-white/30 mb-1">CPU / Execution</div>
              <div className="text-lg font-bold text-white">{(report.cost_analysis.estimated_cpu_pct_per_execution || 0).toFixed(1)}<span className="text-xs text-white/30 font-normal">%</span></div>
            </div>
            <div className="p-3 rounded-lg bg-white-5">
              <div className="text-[10px] uppercase tracking-wider text-white/30 mb-1">Query Features</div>
              <div className="flex flex-wrap gap-1 mt-1">
                {report.cost_analysis.has_wildcards && <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 text-[10px]">Wildcards</span>}
                {report.cost_analysis.has_regex && <span className="px-1.5 py-0.5 rounded bg-orange-500/10 text-orange-400 text-[10px]">Regex</span>}
                {report.cost_analysis.has_joins && <span className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-400 text-[10px]">Joins/Sequences</span>}
                {report.cost_analysis.has_nested_aggregations && <span className="px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 text-[10px]">Nested Aggs</span>}
                {!report.cost_analysis.has_wildcards && !report.cost_analysis.has_regex && !report.cost_analysis.has_joins && !report.cost_analysis.has_nested_aggregations && <span className="text-xs text-white/20">None</span>}
              </div>
            </div>
          </div>
          {report.cost_analysis.notes && (
            <p className="mt-3 text-xs text-white/40">{report.cost_analysis.notes}</p>
          )}
        </div>
      )}
    </div>
  )
}

function StatCard({ label, value, icon }) {
  return (
    <div className="glass-card p-4">
      <div className="flex items-center gap-2 text-white/30 mb-2">
        {icon}
        <span className="text-xs uppercase tracking-wider font-medium">{label}</span>
      </div>
      <div className="text-2xl font-bold text-white">{value}</div>
    </div>
  )
}

// ── KQL extraction (mirrors backend _extract_kql) ────────────────────────
function extractKql(recommendations) {
  if (!recommendations?.length) return []
  const results = []
  for (const rec of recommendations) {
    const regex = /```json\s*(\{[^`]*?"entries"[^`]*?\})\s*```/gs
    let match
    while ((match = regex.exec(rec)) !== null) {
      try {
        const data = JSON.parse(match[1])
        const entries = data.entries || []
        if (!entries.length) continue
        const kqlParts = entries.map(e => {
          const { field = '', value = '', type = 'match' } = e
          if (type === 'match') return `${field}: "${value}"`
          if (type === 'match_any') {
            const vals = value.split(',').map(v => `"${v.trim()}"`).join(' OR ')
            return `${field}: (${vals})`
          }
          if (type === 'wildcard') return `${field}: "${value}"`
          if (type === 'exists') return `${field}: *`
          return `${field}: "${value}"`
        })
        results.push({
          kql: kqlParts.join(' AND '),
          entries,
          entriesJson: JSON.stringify(data, null, 2),
          fields: entries.map(e => [e.field || '', e.value || '']),
        })
      } catch { /* skip malformed JSON */ }
    }
  }
  return results
}

function ExclusionSection({ report, analysisId }) {
  const [selected, setSelected] = useState({})
  const [applying, setApplying] = useState(false)
  const [result, setResult] = useState(null)
  const [copied, setCopied] = useState(null)

  const exclusions = extractKql(report.recommendations)
  if (!exclusions.length) return null

  // Initialize all selected on first render
  if (Object.keys(selected).length === 0 && exclusions.length > 0) {
    const init = {}
    exclusions.forEach((_, i) => { init[i] = true })
    // Use a timeout to avoid setState during render
    setTimeout(() => setSelected(init), 0)
  }

  const allSelected = exclusions.every((_, i) => selected[i])
  const toggleAll = () => {
    const next = {}
    exclusions.forEach((_, i) => { next[i] = !allSelected })
    setSelected(next)
  }

  const handleApply = async () => {
    // Send entries as grouped arrays — each group = one exception item in Kibana
    const selectedGroups = exclusions
      .filter((_, i) => selected[i])
      .map(exc => exc.entries)
    if (!selectedGroups.length) return

    setApplying(true)
    setResult(null)
    try {
      const res = await fetch('/api/exception/apply-recommended', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rule_name: report.rule_name || '',
          rule_id: report.rule_id || '',
          analysis_id: analysisId,
          entries: selectedGroups,
        }),
      })
      const data = await res.json()
      if (res.ok && data.status === 'applied') {
        const linkMsg = data.rule_linked
          ? 'Exception linked to rule ✓'
          : ' (shared list created — link it to the rule in Kibana)'
        setResult({ ok: true, message: (data.message || `Created ${selectedGroups.length} exception items`) + ' — ' + linkMsg })
      } else {
        setResult({ ok: false, message: data.error || 'Failed to apply exceptions' })
      }
    } catch (err) {
      setResult({ ok: false, message: err.message })
    }
    setApplying(false)
  }

  const copyKql = (kql, idx) => {
    navigator.clipboard.writeText(kql)
    setCopied(idx)
    setTimeout(() => setCopied(null), 2000)
  }

  return (
    <div className="glass-card p-5 animate-in" style={{ animationDelay: '0.28s' }}>
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-white">Exclusion Queries</h3>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-1.5 text-xs text-white/40 cursor-pointer">
            <input type="checkbox" checked={allSelected} onChange={toggleAll} className="accent-cyan-500 cursor-pointer" />
            Select all
          </label>
          <button
            onClick={handleApply}
            disabled={applying || !exclusions.some((_, i) => selected[i])}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-cyan-glow/15 text-cyan-glow border border-cyan-glow/30 hover:bg-cyan-glow/25 transition-colors disabled:opacity-30 cursor-pointer"
          >
            {applying ? 'Applying...' : 'Apply Selected to Kibana'}
          </button>
        </div>
      </div>

      <p className="text-xs text-white/30 mb-3">Select which exceptions to push to Kibana, or copy the KQL for manual use.</p>

      {result && (
        <div className={`mb-3 px-4 py-2.5 rounded-lg text-xs ${result.ok ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : 'bg-red-500/10 text-red-400 border border-red-500/20'}`}>
          {result.message}
        </div>
      )}

      <div className="space-y-3">
        {exclusions.map((exc, i) => (
          <div key={i} className="p-4 rounded-xl bg-white-5 border border-white-8">
            <div className="flex items-center gap-2 mb-2">
              <input
                type="checkbox"
                checked={!!selected[i]}
                onChange={() => setSelected(s => ({ ...s, [i]: !s[i] }))}
                className="accent-cyan-500 cursor-pointer"
              />
              <span className="text-xs font-mono text-white/40">Exclusion {i + 1}</span>
              {exc.fields.map(([field], fi) => (
                <span key={fi} className="px-1.5 py-0.5 rounded bg-violet-glow/10 text-violet-glow text-[10px] font-mono">{field}</span>
              ))}
            </div>

            {/* KQL */}
            <div className="mb-2">
              <label className="text-[10px] text-white/20 uppercase tracking-wider">KQL Query</label>
              <div className="relative mt-1">
                <pre className="bg-black/30 rounded-lg p-3 pr-20 text-xs font-mono text-cyan-glow/80 overflow-x-auto">{exc.kql}</pre>
                <button
                  onClick={() => copyKql(exc.kql, i)}
                  className="absolute top-2 right-2 px-2 py-1 text-[10px] bg-cyan-glow/20 text-cyan-glow rounded hover:bg-cyan-glow/30 transition-colors cursor-pointer"
                >
                  {copied === i ? 'Copied!' : 'Copy'}
                </button>
              </div>
            </div>

            {/* Collapsible JSON */}
            <details className="cursor-pointer">
              <summary className="text-[10px] text-white/20 uppercase tracking-wider hover:text-white/40 transition-colors">
                Exception List JSON (API)
              </summary>
              <pre className="bg-black/30 rounded-lg p-3 mt-1 text-xs font-mono text-white/50 overflow-x-auto">{exc.entriesJson}</pre>
            </details>
          </div>
        ))}
      </div>
    </div>
  )
}

function Row({ label, value }) {
  return (
    <div className="flex justify-between">
      <span className="text-white/30">{label}</span>
      <span className="text-white/70 font-mono text-xs">{value}</span>
    </div>
  )
}

function VerdictBadgeLarge({ verdict }) {
  const config = {
    approve: { icon: CheckCircle, color: 'text-emerald-400', bg: 'bg-emerald-500/15 border-emerald-500/30' },
    review: { icon: Eye, color: 'text-amber-400', bg: 'bg-amber-500/15 border-amber-500/30' },
    tune: { icon: Wrench, color: 'text-cyan-glow', bg: 'bg-cyan-glow/10 border-cyan-glow/30' },
    reject: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/15 border-red-500/30' },
    error: { icon: AlertTriangle, color: 'text-white/30', bg: 'bg-white/5 border-white/10' },
  }
  const c = config[verdict] || config.error
  const Icon = c.icon
  return (
    <div className={`flex items-center gap-2 px-4 py-2 rounded-xl border ${c.bg}`}>
      <Icon size={18} className={c.color} />
      <span className={`text-sm font-semibold uppercase tracking-wider ${c.color}`}>{verdict}</span>
    </div>
  )
}

function CostLevelBadge({ level }) {
  const styles = {
    low: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  }
  return (
    <span className={`inline-block px-2.5 py-1 rounded-lg text-sm font-bold uppercase tracking-wider border ${styles[level] || styles.low}`}>
      {level || '—'}
    </span>
  )
}
