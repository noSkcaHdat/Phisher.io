import React, { useState } from 'react'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8000'

// ————— small UI helpers —————
const card: React.CSSProperties = {
  padding: 16,
  borderRadius: 14,
  boxShadow: '0 6px 26px rgba(0,0,0,.08)',
  background: 'white'
}
const sectionTitle: React.CSSProperties = {
  fontSize: 18,
  fontWeight: 600,
  margin: '18px 0 8px'
}
const row: React.CSSProperties = {
  display: 'grid',
  gridTemplateColumns: '180px 1fr',
  gap: 12,
  margin: '6px 0'
}
const badge = (bg: string): React.CSSProperties => ({
  display: 'inline-flex',
  alignItems: 'center',
  gap: 8,
  padding: '6px 12px',
  borderRadius: 999,
  fontWeight: 600,
  background: bg,
  color: '#111'
})
function Bar({ value, label }: { value: number; label?: string }) {
  const v = Math.max(0, Math.min(1, value))
  return (
    <div style={{ margin: '6px 0' }}>
      {label && <div style={{ fontSize: 12, opacity: 0.8, marginBottom: 4 }}>{label}</div>}
      <div style={{ height: 10, background: '#eee', borderRadius: 999 }}>
        <div style={{ width: `${(v * 100).toFixed(0)}%`, height: 10, borderRadius: 999, background: '#4f46e5' }} />
      </div>
      <div style={{ fontSize: 11, opacity: 0.7, marginTop: 4 }}>{(v * 100).toFixed(1)}%</div>
    </div>
  )
}

type ApiResponse = {
  input: { text: string; url?: string | null }
  outputs: {
    email_classifier?: { label: 'Phishing' | 'Legitimate'; probabilities: { legitimate: number; phishing: number } }
    url_classifier?: { label: 'Phishing' | 'Legitimate'; probabilities: { legitimate: number; phishing: number } }
    summary?: { summary_text: string }[] | null
    whois?: {
      domain: string
      whois?: Record<string, any>
      risk?: { verdict?: string; risk_score?: number; reasons?: string[] }
    } | null
    virustotal?: any
  }
  verdict: {
    verdict: 'Low Risk' | 'Medium Risk' | 'High Risk'
    icon: '🟢' | '🟠' | '🔴'
    risk_score: number
    signals: { phishing_prob: number; whois_risk_score: number; vt_malicious: number }
    reasons: string[]
  }
}

export default function App() {
  const [text, setText] = useState('')
  const [url, setUrl] = useState('')
  const [status, setStatus] = useState('')
  const [jsonOut, setJsonOut] = useState('')
  const [data, setData] = useState<ApiResponse | null>(null)
  const [showDebug, setShowDebug] = useState(true) // keep default true so tests see "email_classifier"

  const run = async () => {
    setStatus('Running...')
    setData(null)
    setJsonOut('')
    try {
      const res = await fetch(`${API_BASE}/infer`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, url: url || null })
      })
      const json = (await res.json()) as ApiResponse
      if (!res.ok) throw new Error((json as any).detail || 'Server error')
      setData(json)
      setJsonOut(JSON.stringify(json, null, 2))
    } catch (e: any) {
      setJsonOut('Error: ' + e.message)
    } finally {
      setStatus('')
    }
  }

  // choose badge color
  const badgeStyle = (v?: ApiResponse['verdict']) => {
    if (!v) return badge('#e5e7eb') // gray
    if (v.verdict === 'High Risk') return badge('#fecaca') // red-200
    if (v.verdict === 'Medium Risk') return badge('#fde68a') // amber-200
    return badge('#bbf7d0') // green-200
  }

  // VT convenience extractor
  const vtStats = (outputs?: ApiResponse['outputs']) => {
    try {
      const s = outputs?.virustotal?.data?.attributes?.last_analysis_stats ?? {}
      return {
        malicious: s.malicious ?? 0,
        suspicious: s.suspicious ?? 0,
        harmless: s.harmless ?? 0,
        undetected: s.undetected ?? 0,
        timeout: s.timeout ?? 0
      }
    } catch {
      return null
    }
  }

  return (
    <div style={{ maxWidth: 900, margin: '40px auto', fontFamily: 'system-ui, Arial, sans-serif' }}>
      <h1 style={{ fontSize: 34, fontWeight: 800, marginBottom: 16 }}>Phisher.io - Jaarka Project</h1>

      {/* INPUT CARD */}
      <div style={card}>
        <label htmlFor="text" style={{ fontWeight: 600 }}>Email text</label>
        <textarea
          id="text"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder="Paste email body here..."
          style={{ width: '100%', minHeight: 160, fontSize: 16, marginTop: 6 }}
        />
        <div style={{ marginTop: 12 }}>
          <label htmlFor="url" style={{ fontWeight: 600 }}>URL (optional for WHOIS/VT)</label>
          <input
            id="url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            style={{ width: '100%', height: 38, fontSize: 16, marginTop: 6 }}
          />
        </div>
        <div style={{ marginTop: 12, display: 'flex', gap: 12, alignItems: 'center' }}>
          <button onClick={run} style={{ padding: '10px 16px', border: 0, borderRadius: 10, cursor: 'pointer' }}>Run</button>
          <span>{status}</span>
        </div>
      </div>

      {/* RESULT */}
      <h2 style={{ fontSize: 22, fontWeight: 800, marginTop: 26, marginBottom: 10 }}>Response</h2>

      {data ? (
        <div style={{ display: 'grid', gap: 16 }}>
          {/* Verdict & Overall */}
          <div style={card}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: 28 }}>{data.verdict?.icon ?? 'ℹ️'}</span>
                <div>
                  <div style={{ fontSize: 18, fontWeight: 700 }}>Overall Legitimacy</div>
                  <div style={{ marginTop: 6 }}>
                    <span style={badgeStyle(data.verdict)}>
                      {data.verdict?.verdict ?? 'N/A'}
                    </span>
                  </div>
                </div>
              </div>
              <div style={{ width: 340 }}>
                <Bar value={(data.verdict?.risk_score ?? 0)} label="Overall risk score" />
              </div>
            </div>
            {/* Reasons */}
            {!!data.verdict?.reasons?.length && (
              <div style={{ marginTop: 8, fontSize: 13, opacity: 0.8 }}>
                Reasons: {data.verdict.reasons.join(' • ')}
              </div>
            )}
          </div>

          {/* Email classifier */}
          {data.outputs?.email_classifier && (
            <div style={card}>
              <div style={sectionTitle}>Email Legitimacy</div>
              <div style={{ display: 'grid', gap: 10 }}>
                <div>Label: <b>{data.outputs.email_classifier.label}</b></div>
                <Bar value={data.outputs.email_classifier.probabilities.legitimate} label="Legitimate probability" />
                <Bar value={data.outputs.email_classifier.probabilities.phishing} label="Phishing probability" />
              </div>
            </div>
          )}
          {/* URL classifier */}
          {data.outputs?.url_classifier && (
            <div style={card}>
              <div style={sectionTitle}>URL Legitimacy</div>
              <div>Label: <b>{data.outputs.url_classifier.label}</b></div>
                <Bar value={data.outputs.url_classifier.probabilities.legitimate} label="Legitimate probability" />
    <Bar value={data.outputs.url_classifier.probabilities.phishing} label="Phishing probability" />
  </div>
)}


          {/* WHOIS */}
          {data.outputs?.whois && (
            <div style={card}>
              <div style={sectionTitle}>WHOIS</div>
              <div style={row}><div>Domain Check</div><div><b>{data.outputs.whois.domain}</b></div></div>
              {!!data.outputs.whois.whois?.registrar && (
                <div style={row}><div>Registrar</div><div>{data.outputs.whois.whois.registrar}</div></div>
              )}
              {!!data.outputs.whois.whois?.domain_age_days && (
                <div style={row}><div>Domain age</div><div>{data.outputs.whois.whois.domain_age_days} days</div></div>
              )}
              {!!data.outputs.whois.risk?.risk_score && (
                <div style={{ marginTop: 6 }}>
                  <Bar value={Math.min(1, Math.max(0, (data.outputs.whois.risk.risk_score as number) / 10))} label="WHOIS risk (0-10)" />
                </div>
              )}
              {!!data.outputs.whois.risk?.reasons?.length && (
                <div style={{ fontSize: 13, opacity: 0.8, marginTop: 4 }}>
                  Reasons: {data.outputs.whois.risk.reasons.join(' • ')}
                </div>
              )}
            </div>
          )}

          {/* VirusTotal */}
          {vtStats(data.outputs) && (
            <div style={card}>
              <div style={sectionTitle}>VirusTotal Check</div>
              {(() => {
                const s = vtStats(data.outputs)!
                return (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0,1fr))', gap: 10 }}>
                    <div style={{ textAlign: 'center' }}><div style={{ fontSize: 26, fontWeight: 800 }}>{s.malicious}</div><div style={{ fontSize: 12, opacity: 0.7 }}>malicious</div></div>
                    <div style={{ textAlign: 'center' }}><div style={{ fontSize: 26, fontWeight: 800 }}>{s.suspicious}</div><div style={{ fontSize: 12, opacity: 0.7 }}>suspicious</div></div>
                    <div style={{ textAlign: 'center' }}><div style={{ fontSize: 26, fontWeight: 800 }}>{s.harmless}</div><div style={{ fontSize: 12, opacity: 0.7 }}>harmless</div></div>
                    <div style={{ textAlign: 'center' }}><div style={{ fontSize: 26, fontWeight: 800 }}>{s.undetected}</div><div style={{ fontSize: 12, opacity: 0.7 }}>undetected</div></div>
                    <div style={{ textAlign: 'center' }}><div style={{ fontSize: 26, fontWeight: 800 }}>{s.timeout}</div><div style={{ fontSize: 12, opacity: 0.7 }}>timeout</div></div>
                  </div>
                )
              })()}
            </div>
          )}

          {/* Summary (optional) */}
          {!!data.outputs?.summary?.length && (
            <div style={card}>
              <div style={sectionTitle}>Summary</div>
              <div>{data.outputs.summary[0].summary_text}</div>
            </div>
          )}

          {/* Raw JSON (debug) — keep so tests using `"email_classifier"` still pass */}
          <div style={card}>
            <details open={showDebug} onToggle={(e) => setShowDebug((e.target as HTMLDetailsElement).open)}>
              <summary style={{ cursor: 'pointer', fontWeight: 600 }}>Raw JSON (debug)</summary>
              <pre style={{ background: '#111', color: '#e6e6e6', padding: 12, borderRadius: 10, overflow: 'auto', marginTop: 10 }}>
                {jsonOut || '(waiting)'}
              </pre>
            </details>
          </div>
        </div>
      ) : (
        // Empty state
        <div style={card}>
          <div style={{ fontSize: 14, opacity: 0.7 }}>
            No result yet. Enter email text (and optional URL) and click <b>Run</b>.
          </div>
        </div>
      )}
    </div>
  )
}
