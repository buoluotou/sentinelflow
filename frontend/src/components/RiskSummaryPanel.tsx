/** AI Risk Summary panel (Step 11.6): display + explicit trigger, no chat.
 *
 * Reads the latest summary on mount (GET only — never an automatic POST);
 * "Generate Risk Summary" POSTs a new one. The backend appends a history row
 * per trigger — the panel always renders whatever the API returns and never
 * edits or overwrites an existing record. No risk score is ever shown here:
 * EventRisk.score (Risk Assessment panel) stays the single official score.
 */
import { useCallback, useEffect, useState } from 'react'
import { generateRiskSummary, getRiskSummary } from '../api/aiRiskSummary'
import { ApiError } from '../api/client'
import type { AIRiskSummary } from '../types/aiRiskSummary'
import { ErrorBanner, LevelBadge, Loading, Panel, formatTime } from './common'

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

export function RiskSummaryPanel({ eventId }: { eventId: string }) {
  const [summary, setSummary] = useState<AIRiskSummary | null>(null)
  const [loadingLatest, setLoadingLatest] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [generating, setGenerating] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoadingLatest(true)
    setLoadError(null)
    getRiskSummary(eventId)
      .then((latest) => {
        if (!cancelled) setSummary(latest)
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

  const generate = useCallback(() => {
    if (generating) return // guard against double clicks stacking requests
    setGenerating(true)
    setActionError(null)
    generateRiskSummary(eventId)
      .then(setSummary) // 201 body is the newest history row — no extra GET
      .catch((e: unknown) => setActionError(friendlyAiError(e)))
      .finally(() => setGenerating(false))
  }, [eventId, generating])

  return (
    <Panel title="AI Risk Summary">
      {loadingLatest ? (
        <Loading />
      ) : (
        <>
          {loadError && <ErrorBanner message={loadError} />}
          {actionError && <ErrorBanner message={actionError} />}

          {summary ? (
            <>
              <div className="kv-grid">
                <div className="kv">
                  <div className="k">Analyst Priority</div>
                  <div className="v">
                    <LevelBadge level={summary.analyst_priority} />
                  </div>
                </div>
                <div className="kv">
                  <div className="k">Confidence</div>
                  <div className="v">{Math.round(summary.confidence * 100)}%</div>
                </div>
                <div className="kv" style={{ gridColumn: '1 / -1' }}>
                  <div className="k">Summary</div>
                  <div className="v">{summary.summary}</div>
                </div>
                <div className="kv" style={{ gridColumn: '1 / -1' }}>
                  <div className="k">Key Findings</div>
                  <div className="v">
                    <ul style={{ margin: 0, paddingLeft: 18 }}>
                      {summary.key_findings.map((finding, i) => (
                        <li key={i}>{finding}</li>
                      ))}
                    </ul>
                  </div>
                </div>
                <div className="kv" style={{ gridColumn: '1 / -1' }}>
                  <div className="k">Risk Drivers</div>
                  <div className="v">
                    {summary.risk_drivers.map((driver) => (
                      <span key={driver} className="badge none mono" style={{ marginRight: 6 }}>
                        {driver}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="kv">
                  <div className="k">Provider</div>
                  <div className="v">{summary.provider}</div>
                </div>
                <div className="kv">
                  <div className="k">Model</div>
                  <div className="v mono">{summary.model}</div>
                </div>
                <div className="kv">
                  <div className="k">Generated At</div>
                  <div className="v">{formatTime(summary.created_at)}</div>
                </div>
              </div>
              <p className="muted" style={{ marginTop: 8, marginBottom: 8 }}>
                Showing the latest summary — generating again appends a new record.
              </p>
            </>
          ) : (
            !loadError && (
              <p className="muted" style={{ marginTop: 0 }}>
                No risk summary generated yet.
              </p>
            )
          )}

          <div className="toolbar" style={{ marginBottom: 0 }}>
            <button className="btn primary" disabled={generating} onClick={generate}>
              {generating ? 'Generating risk summary…' : 'Generate Risk Summary'}
            </button>
          </div>
          {generating && (
            <p className="muted" style={{ marginTop: 8, marginBottom: 0 }}>
              Generating with {summary?.model ?? 'the configured model'}… this may take up to
              60 seconds.
            </p>
          )}
        </>
      )}
    </Panel>
  )
}
