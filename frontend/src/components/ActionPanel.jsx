import { Play, Search, Rocket } from 'lucide-react'

export default function ActionPanel() {
  return (
    <div className="glass-card p-5 flex flex-col justify-between h-full">
      <div>
        <h3 className="text-sm font-semibold text-white mb-1">Actions</h3>
        <p className="text-xs text-white/30 mb-5">Test, analyse, and deploy your rule changes</p>
      </div>

      <div className="flex flex-col gap-3">
        {/* Test Run — Cyan Glow */}
        <button className="btn-glow-cyan flex items-center justify-center gap-2.5 text-sm py-3 animate-pulse-glow">
          <Play size={16} />
          Test Run
        </button>

        {/* Analyse — Ghost */}
        <button className="btn-ghost flex items-center justify-center gap-2.5 text-sm py-3">
          <Search size={16} />
          Analyse Impact
        </button>

        {/* Deploy — Lime Gradient */}
        <button className="btn-deploy flex items-center justify-center gap-2.5 text-sm py-3">
          <Rocket size={16} />
          Deploy to Production
        </button>
      </div>

      {/* Last run info */}
      <div className="mt-4 px-3 py-2.5 rounded-xl bg-white-5 border border-white-8">
        <div className="flex items-center justify-between text-[10px] tracking-wider uppercase">
          <span className="text-white/30">Last test run</span>
          <span className="text-white/50">2 min ago</span>
        </div>
        <div className="flex items-center gap-2 mt-1.5">
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          <span className="text-xs text-white/70">Passed — 0 errors, 3 warnings</span>
        </div>
      </div>
    </div>
  )
}
