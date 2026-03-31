import { useState, useEffect } from 'react'
import { Loader2, Database, Bot, Globe, Plug } from 'lucide-react'
import { getConfig, updateSettings, testEsConnection } from '../api'

export default function SettingsPage() {
  const [config, setConfig] = useState(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [message, setMessage] = useState(null)
  const [esResult, setEsResult] = useState(null)
  const [testingEs, setTestingEs] = useState(false)

  // ES form
  const [esUrl, setEsUrl] = useState('')
  const [esApiKey, setEsApiKey] = useState('')
  const [esUsername, setEsUsername] = useState('')
  const [esPassword, setEsPassword] = useState('')
  const [esIndices, setEsIndices] = useState('')
  const [esLookback, setEsLookback] = useState(7)
  // Kibana form
  const [kibanaUrl, setKibanaUrl] = useState('')
  const [kibanaSpace, setKibanaSpace] = useState('')
  const [kibanaUsername, setKibanaUsername] = useState('')
  const [kibanaPassword, setKibanaPassword] = useState('')
  const [kibanaApiKey, setKibanaApiKey] = useState('')
  // LLM form
  const [llmProvider, setLlmProvider] = useState('openai')
  const [llmBaseUrl, setLlmBaseUrl] = useState('')
  const [llmApiKey, setLlmApiKey] = useState('')
  const [llmModel, setLlmModel] = useState('')
  const [llmTemp, setLlmTemp] = useState(0.2)
  const [llmMaxIter, setLlmMaxIter] = useState(3)

  useEffect(() => {
    getConfig().then((cfg) => {
      setConfig(cfg)
      setEsUrl(cfg?.es?.url || '')
      setEsUsername(cfg?.es?.username || '')
      setEsIndices(cfg?.es?.production_indices || '')
      setEsLookback(cfg?.es?.noise_lookback_days || 7)
      setKibanaUrl(cfg?.es?.kibana_url || '')
      setKibanaSpace(cfg?.es?.kibana_space || '')
      setKibanaUsername(cfg?.es?.kibana_username || '')
      setLlmProvider(cfg?.llm?.provider || 'openai')
      setLlmBaseUrl(cfg?.llm?.base_url || '')
      setLlmModel(cfg?.llm?.deployment_name || '')
      setLlmTemp(cfg?.llm?.temperature || 0.2)
      setLlmMaxIter(cfg?.llm?.max_iterations || 3)
      setLoading(false)
    })
  }, [])

  const handleTestEs = async () => {
    setTestingEs(true)
    const result = await testEsConnection()
    setEsResult(result)
    setTestingEs(false)
  }

  const save = async (section, values) => {
    setSaving(true)
    setMessage(null)
    try {
      const result = await updateSettings(section, values)
      setMessage({ type: 'success', text: result.message || 'Settings updated' })
    } catch (err) {
      setMessage({ type: 'error', text: err.message })
    }
    setSaving(false)
  }

  if (loading) return (
    <div className="flex items-center justify-center h-96">
      <div className="w-8 h-8 border-2 border-cyan-glow/30 border-t-cyan-glow rounded-full animate-spin" />
    </div>
  )

  return (
    <div className="space-y-6 max-w-3xl">
      <header className="animate-in">
        <h1 className="text-2xl font-bold text-white"><span className="text-cyan-glow">Settings</span></h1>
        <p className="text-sm text-white/40 mt-0.5">Configure Elasticsearch, Kibana, and AI connections</p>
      </header>

      {message && (
        <div className={`p-3 rounded-lg border text-sm ${message.type === 'success' ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-red-500/10 border-red-500/20 text-red-400'}`}>
          {message.text}
        </div>
      )}

      {/* ── Elasticsearch ──────────────────── */}
      <div className="glass-card p-6 animate-in" style={{ animationDelay: '0.05s' }}>
        <div className="flex items-center gap-3 mb-5">
          <div className="w-9 h-9 rounded-lg bg-cyan-glow/10 flex items-center justify-center">
            <Database size={18} className="text-cyan-glow" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">Elasticsearch</h3>
            <p className="text-xs text-white/30">Data source for noise queries and alert counts</p>
          </div>
        </div>
        <div className="space-y-3">
          <FormField label="URL" value={esUrl} onChange={setEsUrl} placeholder="https://localhost:9200" />
          <FormField label="API Key" value={esApiKey} onChange={setEsApiKey} placeholder="Leave blank to keep current" type="password" />
          <div className="grid grid-cols-2 gap-3">
            <FormField label="Username" value={esUsername} onChange={setEsUsername} />
            <FormField label="Password" value={esPassword} onChange={setEsPassword} type="password" placeholder="Leave blank to keep current" />
          </div>
          <FormField label="Production Indices" value={esIndices} onChange={setEsIndices} placeholder="logs-*, .alerts-*" />
          <FormField label="Lookback Days" value={esLookback} onChange={(v) => setEsLookback(Number(v))} type="number" />
          <div className="flex gap-3 mt-4">
            <button onClick={() => save('es', { url: esUrl, api_key: esApiKey, username: esUsername, password: esPassword, production_indices: esIndices, noise_lookback_days: esLookback })} disabled={saving} className="btn-glow-cyan text-sm flex items-center gap-2">
              {saving && <Loader2 size={14} className="animate-spin" />} Save ES Settings
            </button>
            <button onClick={handleTestEs} disabled={testingEs} className="btn-ghost text-sm flex items-center gap-2">
              {testingEs ? <Loader2 size={14} className="animate-spin" /> : <Plug size={14} />} Test Connection
            </button>
          </div>
          {esResult && (
            <div className={`p-3 rounded-lg border text-xs mt-3 ${esResult.connected ? 'bg-emerald-500/10 border-emerald-500/20 text-emerald-400' : 'bg-red-500/10 border-red-500/20 text-red-400'}`}>
              {esResult.connected ? `Connected to ${esResult.cluster_name} — Status: ${esResult.status}, Nodes: ${esResult.nodes}` : `Failed: ${esResult.error || 'Unknown error'}`}
            </div>
          )}
        </div>
      </div>

      {/* ── Kibana ─────────────────────────── */}
      <div className="glass-card p-6 animate-in" style={{ animationDelay: '0.1s' }}>
        <div className="flex items-center gap-3 mb-5">
          <div className="w-9 h-9 rounded-lg bg-violet-glow/10 flex items-center justify-center">
            <Globe size={18} className="text-violet-glow" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">Kibana</h3>
            <p className="text-xs text-white/30">Kibana API for browsing and importing detection rules</p>
          </div>
        </div>
        <div className="space-y-3">
          <FormField label="Kibana URL" value={kibanaUrl} onChange={setKibanaUrl} placeholder="https://kibana.example.com:5601" />
          <FormField label="Space" value={kibanaSpace} onChange={setKibanaSpace} placeholder="default" />
          <div className="grid grid-cols-2 gap-3">
            <FormField label="Username" value={kibanaUsername} onChange={setKibanaUsername} />
            <FormField label="Password" value={kibanaPassword} onChange={setKibanaPassword} type="password" placeholder="Leave blank to keep current" />
          </div>
          <FormField label="API Key" value={kibanaApiKey} onChange={setKibanaApiKey} placeholder="Leave blank to keep current" type="password" />
          <button onClick={() => save('kibana', { kibana_url: kibanaUrl, kibana_space: kibanaSpace, kibana_username: kibanaUsername, kibana_password: kibanaPassword, kibana_api_key: kibanaApiKey })} disabled={saving} className="btn-glow-cyan text-sm flex items-center gap-2 mt-4">
            {saving && <Loader2 size={14} className="animate-spin" />} Save Kibana Settings
          </button>
        </div>
      </div>

      {/* ── LLM ────────────────────────────── */}
      <div className="glass-card p-6 animate-in" style={{ animationDelay: '0.15s' }}>
        <div className="flex items-center gap-3 mb-5">
          <div className="w-9 h-9 rounded-lg bg-lime-glow/10 flex items-center justify-center">
            <Bot size={18} className="text-lime-glow" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">AI / LLM</h3>
            <p className="text-xs text-white/30">Language model for agentic investigation and recommendations</p>
          </div>
        </div>
        <div className="space-y-3">
          <div>
            <label className="text-xs text-white/40 block mb-1">Provider</label>
            <select value={llmProvider} onChange={(e) => {
              const p = e.target.value
              setLlmProvider(p)
              const defaults = {
                anthropic_foundry: 'https://anthropic.foundry.your-org.com/v1',
                openai_foundry: 'https://openai.foundry.your-org.com/v1',
                anthropic: 'https://api.anthropic.com',
                openai: 'https://api.openai.com/v1',
              }
              setLlmBaseUrl(defaults[p] || '')
              setLlmModel(p.includes('anthropic') ? 'claude-sonnet-4-20250514' : 'gpt-4o')
            }}
              className="w-full px-3 py-2 rounded-lg bg-white-5 border border-white-10 text-white text-sm focus:outline-none focus:border-cyan-glow/40 cursor-pointer">
              <option value="anthropic_foundry">Claude via Foundry</option>
              <option value="openai_foundry">OpenAI via Foundry</option>
              <option value="anthropic">Claude (Direct API)</option>
              <option value="openai">OpenAI (Direct API)</option>
            </select>
          </div>
          <FormField label="API Endpoint" value={llmBaseUrl} onChange={setLlmBaseUrl} placeholder={llmProvider.includes('anthropic') ? 'https://api.anthropic.com' : 'https://api.openai.com/v1'} />
          <FormField label="API Key" value={llmApiKey} onChange={setLlmApiKey} type="password" placeholder="Leave blank to keep current" />
          <div className="grid grid-cols-3 gap-3">
            <div className="col-span-1">
              <FormField label="Model" value={llmModel} onChange={setLlmModel} placeholder={llmProvider.includes('anthropic') ? 'claude-sonnet-4-20250514' : 'gpt-4o'} />
            </div>
            <FormField label="Temperature" value={llmTemp} onChange={(v) => setLlmTemp(Number(v))} type="number" step="0.1" />
            <FormField label="Max Iterations" value={llmMaxIter} onChange={(v) => setLlmMaxIter(Number(v))} type="number" />
          </div>
          <button onClick={() => save('llm', { provider: llmProvider, base_url: llmBaseUrl, api_key: llmApiKey, deployment_name: llmModel, temperature: llmTemp, max_iterations: llmMaxIter })} disabled={saving} className="btn-glow-cyan text-sm flex items-center gap-2 mt-4">
            {saving && <Loader2 size={14} className="animate-spin" />} Save AI Settings
          </button>
        </div>
      </div>
    </div>
  )
}

function FormField({ label, value, onChange, placeholder = '', type = 'text', step }) {
  return (
    <div>
      <label className="text-xs text-white/40 block mb-1">{label}</label>
      <input type={type} step={step} value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
        className="w-full px-3 py-2 rounded-lg bg-white-5 border border-white-10 text-white text-sm placeholder:text-white/20 focus:outline-none focus:border-cyan-glow/40" />
    </div>
  )
}
