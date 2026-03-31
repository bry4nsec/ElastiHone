/**
 * ElastiHone API client — all calls to the FastAPI backend.
 *
 * In dev, Vite proxies /api/* to localhost:8090.
 * In production, both are served from the same origin.
 */

// ── Health & Config ──────────────────────────────────────────

export async function getHealth() {
  const res = await fetch('/api/health')
  return res.json()
}

export async function getConfig() {
  const res = await fetch('/api/config')
  return res.json()
}

export async function testEsConnection() {
  const res = await fetch('/api/es/test', { method: 'POST' })
  return res.json()
}

export async function updateSettings(section, values) {
  const res = await fetch('/api/settings', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ section, values }),
  })
  return res.json()
}

// ── Analysis ─────────────────────────────────────────────────

export async function submitRule(ruleContent, options = {}) {
  const res = await fetch('/api/analyse', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      rule_content: ruleContent,
      format_hint: options.formatHint || 'auto',
      lookback_days: options.lookbackDays || 7,
      index_override: options.indexOverride || '',
    }),
  })
  if (!res.ok) {
    const err = await res.json()
    throw new Error(err.error || 'Analysis submission failed')
  }
  return res.json()
}

export async function pollStatus(analysisId) {
  const res = await fetch(`/api/status/${analysisId}`)
  return res.json()
}

export async function getAnalysis(analysisId) {
  const res = await fetch(`/api/analysis/${analysisId}`)
  if (!res.ok) return null
  return res.json()
}

export async function deleteAnalysis(analysisId) {
  const res = await fetch(`/api/history/${analysisId}`, { method: 'DELETE' })
  return res.json()
}

// ── History ──────────────────────────────────────────────────

export async function getHistory({ page = 1, perPage = 20, search = '', verdict = '', sortBy = 'created_at', sortOrder = 'desc' } = {}) {
  const params = new URLSearchParams({
    page, per_page: perPage, search, verdict, sort_by: sortBy, sort_order: sortOrder,
  })
  const res = await fetch(`/api/history?${params}`)
  return res.json()
}

// ── Metrics ──────────────────────────────────────────────────

export async function getMetrics() {
  const res = await fetch('/api/metrics')
  return res.json()
}

export async function getCoverage() {
  const res = await fetch('/api/rules/coverage')
  return res.json()
}

// ── Elastic Rules (Kibana) ───────────────────────────────────

export async function getRulesJson({ search = '', page = 1, ruleType = '', severity = '', source = '', status = '' } = {}) {
  const params = new URLSearchParams({ search, page, rule_type: ruleType, severity, source, status })
  const res = await fetch(`/api/rules/json?${params}`)
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error || `Failed to fetch rules from Kibana (${res.status})`)
  }
  return res.json()
}

export async function getRule(ruleId) {
  const res = await fetch(`/api/rules/${ruleId}`)
  if (!res.ok) throw new Error('Failed to fetch rule')
  return res.json()
}

// ── Behavioral Rules ─────────────────────────────────────────

export async function getBehavioralRulesJson({ search = '', platform = '', tactic = '', page = 1 } = {}) {
  const params = new URLSearchParams({ search, platform, tactic, page })
  const res = await fetch(`/api/behavioral-rules/json?${params}`)
  if (!res.ok) throw new Error('Failed to fetch behavioral rules')
  return res.json()
}

export async function getBehavioralRule(path) {
  const params = new URLSearchParams({ path })
  const res = await fetch(`/api/behavioral-rules/fetch?${params}`)
  if (!res.ok) throw new Error('Failed to fetch behavioral rule')
  return res.json()
}

export async function getBehavioralTactics() {
  const res = await fetch('/api/behavioral-rules/tactics')
  return res.json()
}

// ── Alert Subtypes ──────────────────────────────────────────

export async function getAlertSubtypes(ruleName, days = 7, ruleUuid = '') {
  const params = new URLSearchParams({ rule_name: ruleName, days })
  if (ruleUuid) params.set('rule_uuid', ruleUuid)
  const res = await fetch(`/api/alerts/subtypes?${params}`)
  return res.json()
}

// ── Polling helper ───────────────────────────────────────────

export async function waitForAnalysis(analysisId, onUpdate, intervalMs = 2000) {
  while (true) {
    const { status } = await pollStatus(analysisId)
    if (onUpdate) onUpdate(status)
    if (status === 'done' || status === 'not_found') {
      return getAnalysis(analysisId)
    }
    await new Promise((r) => setTimeout(r, intervalMs))
  }
}
