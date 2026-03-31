import { useEffect, useState } from 'react'

export default function ConfidenceGauge({ score = 94.2 }) {
  const [animatedScore, setAnimatedScore] = useState(0)
  const radius = 58
  const circumference = 2 * Math.PI * radius

  useEffect(() => {
    const timer = setTimeout(() => setAnimatedScore(score), 200)
    return () => clearTimeout(timer)
  }, [score])

  const offset = circumference - (animatedScore / 100) * circumference
  const scoreColor = score >= 90 ? '#00e5ff' : score >= 70 ? '#f59e0b' : '#ef4444'

  return (
    <div className="glass-card p-5 flex flex-col items-center justify-center h-full">
      <h3 className="text-sm font-semibold text-white mb-4 self-start">Confidence Score</h3>

      <div className="gauge-ring">
        <svg width="140" height="140" viewBox="0 0 140 140">
          <circle className="gauge-bg" cx="70" cy="70" r={radius} />
          <circle
            className="gauge-fill"
            cx="70" cy="70" r={radius}
            stroke={scoreColor}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{
              filter: `drop-shadow(0 0 8px ${scoreColor}40)`,
            }}
          />
        </svg>
        <div className="gauge-label">
          <span className="text-3xl font-bold text-white">{Math.round(animatedScore)}</span>
          <span className="text-xs text-white/40 -mt-0.5">/ 100</span>
        </div>
      </div>

      <div className="flex items-center gap-4 mt-4 text-[10px] font-medium tracking-wider uppercase">
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-emerald-400" />
          <span className="text-white/40">Precision</span>
          <span className="text-white/70">96.1%</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2 h-2 rounded-full bg-cyan-glow" />
          <span className="text-white/40">Recall</span>
          <span className="text-white/70">92.3%</span>
        </div>
      </div>
    </div>
  )
}
