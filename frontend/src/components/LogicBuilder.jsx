import { useState } from 'react'
import { GripVertical, X, Plus } from 'lucide-react'

const initialTiles = [
  { id: 1, type: 'AND', field: 'process.name', op: 'is', value: 'powershell.exe', color: 'cyan' },
  { id: 2, type: 'AND', field: 'process.command_line', op: 'contains', value: 'Invoke-WebRequest', color: 'cyan' },
  { id: 3, type: 'NOT', field: 'user.name', op: 'is', value: 'SYSTEM', color: 'red' },
  { id: 4, type: 'OR', field: 'process.parent.name', op: 'is', value: 'explorer.exe', color: 'violet' },
]

const typeColors = {
  AND: { bg: 'rgba(0,229,255,0.08)', border: 'rgba(0,229,255,0.2)', text: '#00e5ff' },
  OR: { bg: 'rgba(168,85,247,0.08)', border: 'rgba(168,85,247,0.2)', text: '#a855f7' },
  NOT: { bg: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.2)', text: '#ef4444' },
}

export default function LogicBuilder() {
  const [tiles, setTiles] = useState(initialTiles)
  const [dragId, setDragId] = useState(null)

  const removeTile = (id) => setTiles(tiles.filter((t) => t.id !== id))

  const addTile = () => {
    setTiles([
      ...tiles,
      { id: Date.now(), type: 'AND', field: 'field.name', op: 'is', value: 'value', color: 'cyan' },
    ])
  }

  return (
    <div className="glass-card p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-white">Logic Builder</h3>
        <button onClick={addTile} className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white-5 border border-white-10 text-xs text-white/50 hover:text-white/80 hover:border-white/20 transition-all cursor-pointer">
          <Plus size={13} />
          Add Condition
        </button>
      </div>

      <div className="flex flex-wrap gap-2.5">
        {tiles.map((tile) => {
          const colors = typeColors[tile.type]
          return (
            <div
              key={tile.id}
              draggable
              onDragStart={() => setDragId(tile.id)}
              onDragEnd={() => setDragId(null)}
              className={`
                group flex items-center gap-2.5 px-3.5 py-2.5 rounded-xl
                border transition-all duration-300 cursor-grab active:cursor-grabbing
                ${dragId === tile.id ? 'opacity-50 scale-95' : 'opacity-100'}
              `}
              style={{
                background: colors.bg,
                borderColor: colors.border,
              }}
            >
              <GripVertical size={14} className="text-white/20 group-hover:text-white/40" />

              <span
                className="px-1.5 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase"
                style={{ color: colors.text, background: `${colors.text}15` }}
              >
                {tile.type}
              </span>

              <span className="text-xs text-white/60 font-mono">{tile.field}</span>
              <span className="text-[10px] text-white/30 tracking-wider uppercase">{tile.op}</span>
              <span className="text-xs text-white font-medium font-mono">"{tile.value}"</span>

              <button
                onClick={() => removeTile(tile.id)}
                className="ml-1 opacity-0 group-hover:opacity-100 text-white/30 hover:text-red-400 transition-all cursor-pointer"
              >
                <X size={13} />
              </button>
            </div>
          )
        })}
      </div>
    </div>
  )
}
