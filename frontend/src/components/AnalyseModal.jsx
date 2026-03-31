import { useState } from 'react'
import { X, Clock, Database, Zap } from 'lucide-react'

const LOOKBACK_OPTIONS = [
  { value: 1, label: '1 day' },
  { value: 3, label: '3 days' },
  { value: 7, label: '7 days' },
  { value: 14, label: '14 days' },
  { value: 30, label: '30 days' },
]

export default function AnalyseModal({ rule, onConfirm, onClose }) {
  const [lookbackDays, setLookbackDays] = useState(7)
  const [indexOverride, setIndexOverride] = useState('')

  const ruleIndices = rule?.index?.join(', ') || rule?.indices?.join?.(', ') || ''

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm animate-in" onClick={onClose}>
      <div className="glass-card w-full max-w-md p-6 relative" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-center justify-between mb-5">
          <div>
            <h3 className="text-base font-semibold text-white">Analyse Rule</h3>
            <p className="text-xs text-white/30 mt-0.5 max-w-[300px] truncate">{rule?.name || 'Detection Rule'}</p>
          </div>
          <button onClick={onClose} className="p-1.5 rounded-lg hover:bg-white-5 text-white/30 hover:text-white/60 transition-colors cursor-pointer">
            <X size={16} />
          </button>
        </div>

        {/* Lookback Period */}
        <div className="mb-4">
          <label className="flex items-center gap-1.5 text-xs font-medium text-white/50 uppercase tracking-wider mb-2">
            <Clock size={12} /> Lookback Period
          </label>
          <div className="flex gap-1.5">
            {LOOKBACK_OPTIONS.map(opt => (
              <button
                key={opt.value}
                onClick={() => setLookbackDays(opt.value)}
                className={`flex-1 px-2 py-2 rounded-lg text-xs font-medium transition-all cursor-pointer
                  ${lookbackDays === opt.value
                    ? 'bg-cyan-glow/15 text-cyan-glow border border-cyan-glow/30'
                    : 'bg-white-5 text-white/40 border border-transparent hover:border-white-10 hover:text-white/60'
                  }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {/* Index Override */}
        <div className="mb-5">
          <label className="flex items-center gap-1.5 text-xs font-medium text-white/50 uppercase tracking-wider mb-2">
            <Database size={12} /> Index Pattern
          </label>
          <input
            type="text"
            value={indexOverride}
            onChange={e => setIndexOverride(e.target.value)}
            placeholder={ruleIndices || 'Use rule default indices'}
            className="w-full px-3 py-2 rounded-xl bg-white-5 border border-white-10 text-white text-sm placeholder:text-white/20 focus:outline-none focus:border-cyan-glow/40"
          />
          <p className="text-[10px] text-white/20 mt-1">
            Leave empty to use the rule's configured indices{ruleIndices ? `: ${ruleIndices}` : ''}
          </p>
        </div>

        {/* Actions */}
        <div className="flex gap-2">
          <button onClick={onClose} className="btn-ghost text-sm flex-1 py-2.5 cursor-pointer">Cancel</button>
          <button
            onClick={() => onConfirm({ lookbackDays, indexOverride })}
            className="btn-glow-cyan text-sm flex-1 py-2.5 flex items-center justify-center gap-2 cursor-pointer"
          >
            <Zap size={14} /> Start Analysis
          </button>
        </div>
      </div>
    </div>
  )
}
