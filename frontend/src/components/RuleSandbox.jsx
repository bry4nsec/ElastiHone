import { useState } from 'react'
import Editor from '@monaco-editor/react'

const SAMPLE_RULE = `{
  "name": "Suspicious PowerShell Download",
  "type": "query",
  "language": "kuery",
  "query": "process.name: powershell.exe AND process.command_line: (*Invoke-WebRequest* OR *wget* OR *curl*)",
  "severity": "high",
  "risk_score": 73,
  "index": ["logs-endpoint.events.*"],
  "threat": [{
    "framework": "MITRE ATT&CK",
    "tactic": { "id": "TA0002", "name": "Execution" },
    "technique": [{
      "id": "T1059.001",
      "name": "PowerShell"
    }]
  }],
  "alert_suppression": {
    "group_by": ["host.hostname", "user.name"],
    "duration": { "value": 5, "unit": "m" }
  }
}`

export default function RuleSandbox() {
  const [code, setCode] = useState(SAMPLE_RULE)

  return (
    <div className="glass-card h-full flex flex-col overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-white-8">
        <div className="flex items-center gap-3">
          <h3 className="text-sm font-semibold text-white">Rule Editor</h3>
          <span className="px-2 py-0.5 rounded-full bg-cyan-glow/10 text-cyan-glow text-[10px] font-semibold tracking-wider uppercase">
            Elastic DSL
          </span>
        </div>
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
          <div className="w-2.5 h-2.5 rounded-full bg-yellow-500/60" />
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/60" />
        </div>
      </div>

      {/* Monaco Editor */}
      <div className="flex-1 min-h-[380px]">
        <Editor
          height="100%"
          defaultLanguage="json"
          value={code}
          onChange={(val) => setCode(val || '')}
          theme="vs-dark"
          options={{
            fontSize: 13,
            fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            padding: { top: 16, bottom: 16 },
            lineNumbers: 'on',
            renderLineHighlight: 'gutter',
            bracketPairColorization: { enabled: true },
            smoothScrolling: true,
            cursorSmoothCaretAnimation: 'on',
            overviewRulerBorder: false,
            hideCursorInOverviewRuler: true,
            scrollbar: {
              verticalScrollbarSize: 6,
              horizontalScrollbarSize: 6,
            },
          }}
        />
      </div>
    </div>
  )
}
