/** Incident AI Investigation panel (Phase 2 Step 14.5): observe / review /
 * audit — NEVER decide / execute.
 *
 * Consumes the single read-only endpoint GET /incidents/{id}/ai-context and
 * renders the complete case context: AI Explanation history, Risk Summary
 * history, Response Recommendation history with their Approval audit trail.
 *
 * Frozen boundaries enforced by this component:
 * - GET-only on mount; no automatic POST of any kind
 * - histories are rendered COMPLETE (newest first for readability, but every
 *   record stays in state — never "latest overwrites previous")
 * - approval === null renders as "Pending Review" — a derived UI label, never
 *   a status sent back to the backend (the Approval Queue owns decisions)
 * - no Execute / Approve / Reject affordance exists here at all
 * - only the snapshot score is shown; the UI never recomputes risk
 */
import { useEffect, useState } from 'react'
import { getIncidentAIContext } from '../api/incidents'
import type { IncidentAIContext } from '../types/incidentAIContext'
import type { RecommendationWithApproval } from '../types/incidentAIContext'
import { actionLabel } from './ResponseRecommendationPanel'
import { ErrorBanner, LevelBadge, Loading, Panel, formatTime } from './common'

/** Approval audit chip. Display-only: "pending" here is the derived state
 * (approval === null) — there is no stored pending status anywhere. */
function ApprovalBadge({ entry }: { entry: RecommendationWithApproval }) {
  const { approval } = entry
  if (approval === null) return <span className="badge none">Pending Review</span>
  if (approval.status === 'approved') return <span className="badge low">Approved</span>
  return <span className="badge high">Rejected</span>
}

export function IncidentAIContextPanel({ incidentId }: { incidentId: string }) {
  const [context, setContext] = useState<IncidentAIContext | null>(null)
  const [loading, setLoading] = useState(true)
  const [loadError, setLoadError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setLoadError(null)
    getIncidentAIContext(incidentId)
      .then((data) => {
        if (!cancelled) setContext(data)
      })
      .catch((e: unknown) => {
        // ApiError already carries the backend detail verbatim (e.g. 404
        // "Incident not found"); surface it without a second interpretation.
        if (!cancelled) setLoadError(e instanceof Error ? e.message : String(e))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [incidentId])

  return (
    <Panel title="AI Investigation">
      {loading ? (
        <>
          <Loading />
          <p className="muted" style={{ marginTop: 0 }}>
            Loading AI context…
          </p>
        </>
      ) : (
        <>
          {loadError && <ErrorBanner message={loadError} />}

          {context && (
            <>
              <p className="muted" style={{ marginTop: 0 }}>
                Risk Score (snapshot): <strong>{context.incident.risk_score_snapshot}</strong>{' '}
                — copied from the event risk assessment when the case was opened; AI never
                recomputes it.
              </p>

              {context.analyses.length === 0 &&
              context.risk_summaries.length === 0 &&
              context.response_recommendations.length === 0 ? (
                <p className="muted" style={{ margin: 0 }}>
                  No AI analysis available yet.
                </p>
              ) : (
                <>
                  {context.analyses.length > 0 && (
                    <>
                      <h3>AI Explanation History ({context.analyses.length})</h3>
                      {[...context.analyses].reverse().map((analysis, i) => (
                        <div key={analysis.id} className="kv-grid" style={{ marginBottom: 12 }}>
                          <div className="kv" style={{ gridColumn: '1 / -1' }}>
                            <div className="k">
                              Analysis #{context.analyses.length - i} ·{' '}
                              {formatTime(analysis.created_at)}
                            </div>
                            <div className="v">{analysis.summary}</div>
                          </div>
                          <div className="kv">
                            <div className="k">Attack Type</div>
                            <div className="v">{analysis.attack_type}</div>
                          </div>
                          <div className="kv">
                            <div className="k">Confidence</div>
                            <div className="v">{Math.round(analysis.confidence * 100)}%</div>
                          </div>
                          {analysis.why_risky.length > 0 && (
                            <div className="kv" style={{ gridColumn: '1 / -1' }}>
                              <div className="k">Why Risky</div>
                              <div className="v">
                                <ul style={{ margin: 0, paddingLeft: 18 }}>
                                  {analysis.why_risky.map((reason, j) => (
                                    <li key={j}>{reason}</li>
                                  ))}
                                </ul>
                              </div>
                            </div>
                          )}
                        </div>
                      ))}
                    </>
                  )}

                  {context.risk_summaries.length > 0 && (
                    <>
                      <h3>Risk Summary History ({context.risk_summaries.length})</h3>
                      {[...context.risk_summaries].reverse().map((summary, i) => (
                        <div key={summary.id} className="kv-grid" style={{ marginBottom: 12 }}>
                          <div className="kv" style={{ gridColumn: '1 / -1' }}>
                            <div className="k">
                              Summary #{context.risk_summaries.length - i} ·{' '}
                              {formatTime(summary.created_at)}
                            </div>
                            <div className="v">{summary.summary}</div>
                          </div>
                          {summary.key_findings.length > 0 && (
                            <div className="kv" style={{ gridColumn: '1 / -1' }}>
                              <div className="k">Key Findings</div>
                              <div className="v">
                                <ul style={{ margin: 0, paddingLeft: 18 }}>
                                  {summary.key_findings.map((finding, j) => (
                                    <li key={j}>{finding}</li>
                                  ))}
                                </ul>
                              </div>
                            </div>
                          )}
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
                        </div>
                      ))}
                    </>
                  )}

                  {context.response_recommendations.length > 0 && (
                    <>
                      <h3>
                        Response Recommendation History (
                        {context.response_recommendations.length})
                      </h3>
                      {[...context.response_recommendations].reverse().map((entry, i) => (
                        <div key={entry.recommendation.id} style={{ marginBottom: 12 }}>
                          <div className="kv-grid">
                            <div className="kv" style={{ gridColumn: '1 / -1' }}>
                              <div className="k">
                                Recommendation #{context.response_recommendations.length - i} ·{' '}
                                {formatTime(entry.recommendation.created_at)}
                              </div>
                              <div className="v">{entry.recommendation.overall_rationale}</div>
                            </div>
                            <div className="kv" style={{ gridColumn: '1 / -1' }}>
                              <div className="k">Recommended Actions</div>
                              <div className="v">
                                {entry.recommendation.recommendations.length === 0 ? (
                                  <p className="muted" style={{ margin: 0 }}>
                                    No response action warranted.
                                  </p>
                                ) : (
                                  <table className="data">
                                    <thead>
                                      <tr>
                                        <th>Action</th>
                                        <th>Target</th>
                                        <th>Rationale</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {entry.recommendation.recommendations.map((item, j) => (
                                        <tr key={j}>
                                          <td>{actionLabel(item.action)}</td>
                                          <td className="mono">{item.target}</td>
                                          <td className="muted">{item.rationale}</td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                )}
                              </div>
                            </div>
                            <div className="kv">
                              <div className="k">Approval</div>
                              <div className="v">
                                <ApprovalBadge entry={entry} />
                              </div>
                            </div>
                            {entry.approval && (
                              <>
                                <div className="kv">
                                  <div className="k">Reviewer</div>
                                  <div className="v">{entry.approval.reviewer}</div>
                                </div>
                                <div className="kv">
                                  <div className="k">Reviewed At</div>
                                  <div className="v">{formatTime(entry.approval.reviewed_at)}</div>
                                </div>
                                {entry.approval.review_comment && (
                                  <div className="kv" style={{ gridColumn: '1 / -1' }}>
                                    <div className="k">Review Comment</div>
                                    <div className="v">{entry.approval.review_comment}</div>
                                  </div>
                                )}
                              </>
                            )}
                          </div>
                          <p className="muted" style={{ marginTop: 4, marginBottom: 0 }}>
                            Advisory only — decisions are made in the Approval Queue; this view
                            is read-only.
                          </p>
                        </div>
                      ))}
                    </>
                  )}
                </>
              )}
            </>
          )}
        </>
      )}
    </Panel>
  )
}
