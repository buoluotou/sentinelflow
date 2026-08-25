/** AI Alert Explanation panel (Step 10.7): display + explicit trigger, no chat.
 *
 * Reads the latest analysis on mount; "Analyze with AI" POSTs a new one.
 * The backend appends a history row per trigger — the panel always renders
 * whatever the API returns and never edits or fakes an existing record.
 */
import { useCallback, useEffect, useState } from 'react'
import { createAnalysis, getLatestAnalysis } from '../api/aiAnalysis'
import { ApiError } from '../api/client'
import type { AIAnalysis } from '../types/aiAnalysis'
import { ErrorBanner, Loading, Panel, formatTime } from './common'

/** Backend contract -> operator-readable message.
 *
 * The API layer already renders human-readable details ("AI provider
 * unavailable: ...", "AI response did not match the expected protocol: ..."),
 * so surface them verbatim — adding another prefix would duplicate it.
 */
function friendlyAiError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 404) return `Event not found: ${e.message}`
    return e.message
  }
  return e instanceof Error ? e.message : String(e)
}

export function AiAnalysisPanel({ eventId }: { eventId: string }) {
  const [analysis, setAnalysis] = useState<AIAnalysis | null>(null)
  const [loadingLatest, setLoadingLatest] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoadingLatest(true)
    setLoadError(null)
    getLatestAnalysis(eventId)
      .then((latest) => {
        if (!cancelled) setAnalysis(latest)
      })
      .catch((e: unknown) => {
        if (!cancelled) setLoadError(friendlyAiError(e))
      })
      .finally(() => {
        if (!cancelled) setLoadingLatest(false)
      })
    return () => {
      cancelled = true
    }
  }, [eventId])

  const analyze = useCallback(() => {
    if (analyzing) return // guard against double clicks stacking requests
    setAnalyzing(true)
    setActionError(null)
    createAnalysis(eventId)
      .then(setAnalysis) // 201 body is the newest history row
      .catch((e: unknown) => setActionError(friendlyAiError(e)))
      .finally(() => setAnalyzing(false))
  }, [eventId, analyzing])

  return (
    <Panel title="AI Alert Explanation">
      {loadingLatest ? (
        <Loading />
      ) : (
        <>
          {loadError && <ErrorBanner message={loadError} />}
          {actionError && <ErrorBanner message={actionError} />}

          {analysis ? (
            <>
              <div className="kv-grid">
                <div className="kv">
                  <div className="k">Attack Type</div>
                  <div className="v">{analysis.attack_type}</div>
                </div>
                <div className="kv">
                  <div className="k">Confidence</div>
                  <div className="v">{Math.round(analysis.confidence * 100)}%</div>
                </div>
                <div className="kv" style={{ gridColumn: '1 / -1' }}>
                  <div className="k">Summary</div>
                  <div className="v">{analysis.summary}</div>
                </div>
                <div className="kv" style={{ gridColumn: '1 / -1' }}>
                  <div className="k">Why Risky</div>
                  <div className="v">
                    <ul style={{ margin: 0, paddingLeft: 18 }}>
                      {analysis.why_risky.map((reason, i) => (
                        <li key={i}>{reason}</li>
                      ))}
                    </ul>
                  </div>
                </div>
                <div className="kv">
                  <div className="k">Provider</div>
                  <div className="v">{analysis.provider}</div>
                </div>
                <div className="kv">
                  <div className="k">Model</div>
                  <div className="v mono">{analysis.model}</div>
                </div>
                <div className="kv">
                  <div className="k">Analyzed At</div>
                  <div className="v">{formatTime(analysis.created_at)}</div>
                </div>
              </div>
              <p className="muted" style={{ marginTop: 8, marginBottom: 8 }}>
                Showing the latest analysis — re-analysing appends a new record.
              </p>
            </>
          ) : (
            !loadError && (
              <p className="muted" style={{ marginTop: 0 }}>
                No AI analysis recorded for this event yet.
              </p>
            )
          )}

          <div className="toolbar" style={{ marginBottom: 0 }}>
            <button className="btn primary" disabled={analyzing} onClick={analyze}>
              {analyzing ? 'Analyzing…' : 'Analyze with AI'}
            </button>
          </div>
          {analyzing && (
            <p className="muted" style={{ marginTop: 8, marginBottom: 0 }}>
              Analyzing with {analysis?.model ?? 'the configured model'}… this may take up to
              60 seconds.
            </p>
          )}
        </>
      )}
    </Panel>
  )
}
