/** Response Recommendation panel (Step 12.5): display + explicit trigger.
 *
 * Reads the latest recommendation on mount (GET only — never an automatic
 * POST); "Generate Response Recommendation" POSTs a new one. The backend
 * appends a history row per trigger — the panel always renders whatever the
 * API returns and never edits or overwrites an existing record.
 *
 * Advisory only: the six frozen actions render as readable labels, but the
 * panel never executes anything — no Execute/Block/Isolate affordance exists
 * here; every action stays a suggestion until human approval (Step 13).
 * An empty recommendations list is a SUCCESS ("no action warranted"), which
 * is a different state from the 404 "nothing generated yet" empty state.
 */
import { useCallback, useEffect, useState } from 'react'
import {
  generateResponseRecommendation,
  getResponseRecommendation,
} from '../api/responseRecommendation'
import { ApiError } from '../api/client'
import type {
  AIResponseRecommendation,
  ResponseAction,
} from '../types/responseRecommendation'
import { ErrorBanner, Loading, Panel, formatTime } from './common'

/** Display-layer mapping of the frozen 12.1 vocabulary — NOT a new protocol
 * enum; unknown actions fall back to the raw value instead of inventing
 * semantics. */
const ACTION_LABELS: Record<ResponseAction, string> = {
  block_source_ip: 'Block Source IP',
  isolate_host: 'Isolate Host',
  disable_account: 'Disable Account',
  hunt_related_activity: 'Hunt Related Activity',
  escalate_to_incident: 'Escalate to Incident',
  monitor_only: 'Monitor Only',
}

function actionLabel(action: string): string {
  return ACTION_LABELS[action as ResponseAction] ?? action
}

/** Backend contract -> operator-readable message (same as Step 11.6).
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

export function ResponseRecommendationPanel({ eventId }: { eventId: string }) {
  const [recommendation, setRecommendation] =
    useState<AIResponseRecommendation | null>(null)
  const [loadingLatest, setLoadingLatest] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [generating, setGenerating] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoadingLatest(true)
    setLoadError(null)
    getResponseRecommendation(eventId)
      .then((latest) => {
        if (!cancelled) setRecommendation(latest)
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
    generateResponseRecommendation(eventId)
      .then(setRecommendation) // 201 body is the newest history row — no extra GET
      .catch((e: unknown) => setActionError(friendlyAiError(e)))
      .finally(() => setGenerating(false))
  }, [eventId, generating])

  return (
    <Panel title="Response Recommendation">
      {loadingLatest ? (
        <Loading />
      ) : (
        <>
          {loadError && <ErrorBanner message={loadError} />}
          {actionError && <ErrorBanner message={actionError} />}

          {recommendation ? (
            <>
              <div className="kv-grid">
                <div className="kv" style={{ gridColumn: '1 / -1' }}>
                  <div className="k">Overall Rationale</div>
                  <div className="v">{recommendation.overall_rationale}</div>
                </div>
                <div className="kv" style={{ gridColumn: '1 / -1' }}>
                  <div className="k">Recommended Actions</div>
                  <div className="v">
                    {recommendation.recommendations.length === 0 ? (
                      <p className="muted" style={{ margin: 0 }}>
                        No response action warranted.
                      </p>
                    ) : (
                      recommendation.recommendations.map((item, i) => (
                        <div key={i} style={{ marginBottom: 8 }}>
                          <span className="badge none mono">{actionLabel(item.action)}</span>
                          <div className="muted" style={{ marginTop: 4 }}>
                            Target: <span className="mono">{item.target}</span>
                          </div>
                          <div className="muted">Rationale: {item.rationale}</div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
                <div className="kv">
                  <div className="k">Confidence</div>
                  <div className="v">{Math.round(recommendation.confidence * 100)}%</div>
                </div>
                <div className="kv">
                  <div className="k">Provider</div>
                  <div className="v">{recommendation.provider}</div>
                </div>
                <div className="kv">
                  <div className="k">Model</div>
                  <div className="v mono">{recommendation.model}</div>
                </div>
                <div className="kv">
                  <div className="k">Generated At</div>
                  <div className="v">{formatTime(recommendation.created_at)}</div>
                </div>
              </div>
              <p className="muted" style={{ marginTop: 8, marginBottom: 8 }}>
                Advisory only — every action requires human approval before any
                execution. Generating again appends a new record.
              </p>
            </>
          ) : (
            !loadError && (
              <p className="muted" style={{ marginTop: 0 }}>
                No recommendation generated yet.
              </p>
            )
          )}

          <div className="toolbar" style={{ marginBottom: 0 }}>
            <button className="btn primary" disabled={generating} onClick={generate}>
              {generating
                ? 'Generating response recommendation…'
                : 'Generate Response Recommendation'}
            </button>
          </div>
          {generating && (
            <p className="muted" style={{ marginTop: 8, marginBottom: 0 }}>
              Generating with {recommendation?.model ?? 'the configured model'}… this may
              take up to 60 seconds.
            </p>
          )}
        </>
      )}
    </Panel>
  )
}
