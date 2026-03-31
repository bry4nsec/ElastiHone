import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, Trash2, ChevronLeft, ChevronRight } from 'lucide-react'
import { getHistory, deleteAnalysis } from '../api'

export default function HistoryPage() {
  const navigate = useNavigate()
  const [data, setData] = useState({ analyses: [], total: 0, page: 1 })
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [verdict, setVerdict] = useState('')
  const [page, setPage] = useState(1)

  const load = async () => {
    setLoading(true)
    try {
      const result = await getHistory({ page, search, verdict })
      setData(result)
    } catch (e) {
      console.error(e)
    }
    setLoading(false)
  }

  useEffect(() => { load() }, [page, verdict])

  const handleSearch = (e) => {
    e.preventDefault()
    setPage(1)
    load()
  }

  const handleDelete = async (e, id) => {
    e.stopPropagation()
    await deleteAnalysis(id)
    load()
  }

  return (
    <div className="space-y-4">
      <header className="animate-in">
        <h1 className="text-2xl font-bold text-white">Analysis <span className="text-cyan-glow">History</span></h1>
        <p className="text-sm text-white/40 mt-0.5">Browse past detection rule analyses</p>
      </header>

      {/* Filters */}
      <div className="flex items-center gap-3 animate-in" style={{ animationDelay: '0.05s' }}>
        <form onSubmit={handleSearch} className="flex-1 flex gap-2">
          <div className="flex-1 relative">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-white/20" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search rules..."
              className="w-full pl-10 pr-4 py-2 rounded-xl bg-white-5 border border-white-10 text-white text-sm placeholder:text-white/20 focus:outline-none focus:border-cyan-glow/40"
            />
          </div>
          <button type="submit" className="btn-ghost text-sm">Search</button>
        </form>
        <select
          value={verdict}
          onChange={(e) => { setVerdict(e.target.value); setPage(1) }}
          className="px-3 py-2 rounded-xl bg-white-5 border border-white-10 text-white text-sm focus:outline-none appearance-none cursor-pointer"
        >
          <option value="">All verdicts</option>
          <option value="approve">Approve</option>
          <option value="review">Review</option>
          <option value="reject">Reject</option>
          <option value="error">Error</option>
        </select>
      </div>

      {/* Table */}
      <div className="glass-card overflow-hidden animate-in" style={{ animationDelay: '0.1s' }}>
        {loading ? (
          <div className="flex items-center justify-center h-40">
            <div className="w-6 h-6 border-2 border-cyan-glow/30 border-t-cyan-glow rounded-full animate-spin" />
          </div>
        ) : (data.analyses || []).length === 0 ? (
          <div className="p-12 text-center text-white/30">No analyses found</div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-white/30 text-xs uppercase tracking-wider border-b border-white-8">
                <th className="text-left px-5 py-3 font-medium">Rule Name</th>
                <th className="text-left px-5 py-3 font-medium">Verdict</th>
                <th className="text-right px-5 py-3 font-medium">Noise Hits</th>
                <th className="text-right px-5 py-3 font-medium">Alerts/Day</th>
                <th className="text-right px-5 py-3 font-medium">Date</th>
                <th className="px-5 py-3" />
              </tr>
            </thead>
            <tbody>
              {(data.analyses || []).map((item) => (
                <tr
                  key={item.id}
                  onClick={() => navigate(`/report/${item.id}`)}
                  className="border-b border-white-5 hover:bg-white-5 cursor-pointer transition-colors"
                >
                  <td className="px-5 py-3 text-white/80 font-medium max-w-[300px] truncate">{item.rule_name || 'Unknown'}</td>
                  <td className="px-5 py-3"><VerdictBadge verdict={item.verdict} /></td>
                  <td className="px-5 py-3 text-right text-white/60">{item.noise_hits ?? '—'}</td>
                  <td className="px-5 py-3 text-right text-white/60">{(item.alerts_per_day || 0).toFixed(1)}</td>
                  <td className="px-5 py-3 text-right text-white/40 text-xs">{item.created_at ? new Date(item.created_at).toLocaleString() : '—'}</td>
                  <td className="px-5 py-3">
                    <button
                      onClick={(e) => handleDelete(e, item.id)}
                      className="text-white/20 hover:text-red-400 transition-colors cursor-pointer"
                    >
                      <Trash2 size={14} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}

        {/* Pagination */}
        {data.total > (data.per_page || 20) && (
          <div className="flex items-center justify-between px-5 py-3 border-t border-white-8">
            <span className="text-xs text-white/30">{data.total} results</span>
            <div className="flex items-center gap-2">
              <button disabled={page <= 1} onClick={() => setPage(page - 1)} className="p-1 text-white/30 hover:text-white/60 disabled:opacity-30 cursor-pointer">
                <ChevronLeft size={16} />
              </button>
              <span className="text-xs text-white/50">Page {page} of {Math.ceil(data.total / (data.per_page || 20))}</span>
              <button disabled={page >= Math.ceil(data.total / (data.per_page || 20))} onClick={() => setPage(page + 1)} className="p-1 text-white/30 hover:text-white/60 disabled:opacity-30 cursor-pointer">
                <ChevronRight size={16} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function VerdictBadge({ verdict }) {
  const styles = {
    approve: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    review: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    reject: 'bg-red-500/15 text-red-400 border-red-500/30',
    error: 'bg-white/5 text-white/30 border-white/10',
  }
  return (
    <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase tracking-wider border ${styles[verdict] || styles.error}`}>
      {verdict || '—'}
    </span>
  )
}
