import { useNavigate, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, Shield, Settings, History, ShieldAlert
} from 'lucide-react'

const navItems = [
  { id: '/', icon: LayoutDashboard, label: 'Dashboard' },
  { id: '/rules', icon: Shield, label: 'Elastic Rules' },
  { id: '/behavioral-rules', icon: ShieldAlert, label: 'Elastic Agent Rules' },
  { id: '/history', icon: History, label: 'History' },
]

export default function Sidebar() {
  const navigate = useNavigate()
  const location = useLocation()

  return (
    <aside className="fixed left-0 top-0 h-screen w-[72px] bg-charcoal/80 backdrop-blur-xl border-r border-white-8 flex flex-col items-center py-5 z-50">
      <button onClick={() => navigate('/')} className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-glow/20 to-violet-glow/20 border border-cyan-glow/30 flex items-center justify-center mb-8 animate-pulse-glow cursor-pointer">
        <svg width="20" height="20" viewBox="0 0 32 32" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M6 9h20M6 16h14M6 23h9" stroke="#00e5ff" strokeWidth="2.8" strokeLinecap="round"/>
          <circle cx="24" cy="20" r="5.5" stroke="#a855f7" strokeWidth="2"/>
          <path d="M22 20l1.5 1.5 3-3" stroke="#a855f7" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round"/>
        </svg>
      </button>
      <nav className="flex flex-col gap-2 flex-1">
        {navItems.map(({ id, icon: Icon, label }) => {
          const isActive = location.pathname === id
          return (
            <button
              key={id}
              onClick={() => navigate(id)}
              title={label}
              className={`group relative w-11 h-11 rounded-xl flex items-center justify-center transition-all duration-300 cursor-pointer
                ${isActive
                  ? 'bg-cyan-glow/15 text-cyan-glow shadow-[0_0_16px_rgba(0,229,255,0.15)]'
                  : 'text-white/30 hover:text-white/60 hover:bg-white-5'}`}
            >
              <Icon size={20} />
              <span className="absolute left-14 px-2 py-1 rounded-md bg-slate-dark text-xs text-white font-medium opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap border border-white-10">
                {label}
              </span>
            </button>
          )
        })}
      </nav>
      <button
        onClick={() => navigate('/settings')}
        title="Settings"
        className={`w-11 h-11 rounded-xl flex items-center justify-center transition-all duration-300 cursor-pointer
          ${location.pathname === '/settings'
            ? 'bg-cyan-glow/15 text-cyan-glow'
            : 'text-white/30 hover:text-white/60 hover:bg-white-5'}`}
      >
        <Settings size={20} />
      </button>
    </aside>
  )
}
