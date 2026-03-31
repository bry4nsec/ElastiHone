import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar'
import DashboardPage from './pages/DashboardPage'
import ReportPage from './pages/ReportPage'
import HistoryPage from './pages/HistoryPage'
import SettingsPage from './pages/SettingsPage'
import RulesPage from './pages/RulesPage'
import BehavioralRulesPage from './pages/BehavioralRulesPage'

export default function App() {
  return (
    <BrowserRouter>
      <div className="flex h-screen bg-obsidian">
        <Sidebar />
        <main className="flex-1 overflow-y-auto p-6 ml-[72px]">
          <Routes>
            <Route path="/" element={<DashboardPage />} />
            <Route path="/rules" element={<RulesPage />} />
            <Route path="/behavioral-rules" element={<BehavioralRulesPage />} />
            <Route path="/report/:analysisId" element={<ReportPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/settings" element={<SettingsPage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
