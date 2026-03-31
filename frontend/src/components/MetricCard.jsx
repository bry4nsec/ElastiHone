import { TrendingUp, TrendingDown } from 'lucide-react'

const accentColors = {
  cyan: { bg: 'rgba(0,229,255,0.08)', border: 'rgba(0,229,255,0.2)', text: '#00e5ff', glow: 'rgba(0,229,255,0.15)' },
  violet: { bg: 'rgba(168,85,247,0.08)', border: 'rgba(168,85,247,0.2)', text: '#a855f7', glow: 'rgba(168,85,247,0.15)' },
  lime: { bg: 'rgba(132,204,22,0.08)', border: 'rgba(132,204,22,0.2)', text: '#84cc16', glow: 'rgba(132,204,22,0.15)' },
  red: { bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.2)', text: '#ef4444', glow: 'rgba(239,68,68,0.15)' },
}

export default function MetricCard({ title, value, change, positive, icon, accent = 'cyan' }) {
  const colors = accentColors[accent]

  return (
    <div className="glass-card p-5 h-full">
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium tracking-wider uppercase text-white/40">{title}</span>
        <div
          className="w-8 h-8 rounded-lg flex items-center justify-center"
          style={{ background: colors.bg, boxShadow: `0 0 12px ${colors.glow}` }}
        >
          <span style={{ color: colors.text }}>{icon}</span>
        </div>
      </div>
      <div className="text-3xl font-bold text-white tracking-tight">{value}</div>
      <div className={`flex items-center gap-1 mt-2 text-xs font-medium ${positive ? 'text-emerald-400' : 'text-red-400'}`}>
        {positive ? <TrendingUp size={13} /> : <TrendingDown size={13} />}
        <span>{change}</span>
        <span className="text-white/30 ml-1">vs last 7d</span>
      </div>
    </div>
  )
}
