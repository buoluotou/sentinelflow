/** Approval Queue page (Step 13.5): review AI response recommendations.
 *
 * Consumes the frozen Step 13.3 contract:
 * - GET /approvals is the ONLY queue source — pending is a backend
 *   projection, never computed, joined or re-sorted here (backend order:
 *   created_at ASC, id ASC)
 * - Approve/Reject POST { reviewer, review_comment } only; reviewed_at is
 *   never sent (server-stamped)
 * - 201 -> the item leaves the queue locally (no follow-up GET);
 *   409 -> another reviewer won the race, so the server queue is fetched
 *   again as the source of truth
 *
 * Approve != Execute: the recommendations render READ-ONLY (the analyst
 * reviews the AI's original advice, never an edited copy) and the page has
 * no Execute/Block-Now style affordance — execution lands in Step 14.
 */
import { useCallback, useEffect, useState } from 'react'
import {
  approveRecommendation,
  getApprovalQueue,
  rejectRecommendation,
} from '../api/responseApproval'
import { ApiError } from '../api/client'
import type { PendingApproval } from '../types/responseApproval'
import { actionLabel } from '../components/ResponseRecommendationPanel'
import { ErrorBanner, formatTime } from '../components/common'

type DecisionKind = 'approve' | 'reject'

interface Busy {
  id: string
  kind: DecisionKind
}

/** Backend contract -> operator-readable message (same style as Step 11/12). */
function friendlyError(e: unknown): string {
  if (e instanceof ApiError) return e.message
  return e instanceof Error ? e.message : String(e)
}

export function ApprovalQueuePage() {
  const [queue, setQueue] = useState<PendingApproval[] | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)
  /** Page-level reviewer shared by every decision (no auth system yet;
   * swapped for the logged-in identity when RBAC lands). */
  const [reviewer, setReviewer] = useState('analyst-01')
  const [comments, setComments] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState<Busy | null>(null)
  const [itemErrors, setItemErrors] = useState<Record<string, string>>({})

  const loadQueue = useCallback(() => {
    setLoadError(null)
    getApprovalQueue()
      .then((items) => setQueue(items)) // backend order rendered as-is
      .catch((e: unknown) => {
        // A failed load is NEVER presented as an empty queue.
        setQueue(null)
        setLoadError(friendlyError(e))
      })
  }, [])

  useEffect(() => {
    loadQueue()
  }, [loadQueue])

  const refreshQueue = useCallback(() => {
    getApprovalQueue()
      .then((items) => {
        setQueue(items)
        setLoadError(null)
      })
      .catch((e: unknown) => setLoadError(friendlyError(e)))
  }, [])

  const decide = useCallback(
    (item: PendingApproval, kind: DecisionKind) => {
      if (busy) return // buttons are disabled too — double defense
      const trimmedReviewer = reviewer.trim()
      if (!trimmedReviewer) return
      setBusy({ id: item.id, kind })
      setItemErrors((prev) => {
        const next = { ...prev }
        delete next[item.id]
        return next
      })
      const action = kind === 'approve' ? approveRecommendation : rejectRecommendation
      const comment = comments[item.id]?.trim()
      action(item.id, {
        reviewer: trimmedReviewer,
        review_comment: comment ? comment : null, // comment stays optional
      })
        .then(() => {
          // 201: the decision body is authoritative — drop the item locally,
          // no follow-up GET (Step 11/12 "success response updates UI" rule).
          setQueue((prev) => (prev ? prev.filter((q) => q.id !== item.id) : prev))
        })
        .catch((e: unknown) => {
          if (e instanceof ApiError && e.status === 409) {
            // Already reviewed elsewhere: the server queue is the truth.
            refreshQueue()
          } else {
            setItemErrors((prev) => ({ ...prev, [item.id]: friendlyError(e) }))
          }
        })
        .finally(() => setBusy(null))
    },
    [busy, reviewer, comments, refreshQueue],
  )

  const readyReviewer = reviewer.trim().length > 0

  return (
    <>
      <h1 className="page-title">Approval Queue</h1>

      <div className="toolbar">
        <label htmlFor="reviewer">Reviewer</label>
        <input
          id="reviewer"
          value={reviewer}
          onChange={(e) => setReviewer(e.target.value)}
          placeholder="analyst-01"
        />
        <span className="muted">
          {queue === null ? '' : `${queue.length} pending`}
        </span>
      </div>

      {loadError && <ErrorBanner message={loadError} />}

      {queue === null ? (
        !loadError && <p className="muted">Loading approval queue…</p>
      ) : queue.length === 0 ? (
        <p className="muted">No pending recommendations.</p>
      ) : (
        queue.map((item) => {
          const itemBusy = busy?.id === item.id ? busy.kind : null
          const buttonsDisabled = busy !== null || !readyReviewer
          return (
            <div className="panel" key={item.id}>
              <h2>{item.event_title}</h2>

              <div className="kv-grid">
                <div className="kv" style={{ gridColumn: '1 / -1' }}>
                  <div className="k">Overall Rationale</div>
                  <div className="v">{item.overall_rationale}</div>
                </div>
                <div className="kv" style={{ gridColumn: '1 / -1' }}>
                  <div className="k">Recommended Actions</div>
                  <div className="v">
                    {item.recommendations.length === 0 ? (
                      <p className="muted" style={{ margin: 0 }}>
                        No response action warranted.
                      </p>
                    ) : (
                      item.recommendations.map((rec, i) => (
                        <div key={i} style={{ marginBottom: 8 }}>
                          <span className="badge none mono">{actionLabel(rec.action)}</span>
                          <div className="muted" style={{ marginTop: 4 }}>
                            Target: <span className="mono">{rec.target}</span>
                          </div>
                          <div className="muted">Rationale: {rec.rationale}</div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
                <div className="kv">
                  <div className="k">Confidence</div>
                  <div className="v">{Math.round(item.confidence * 100)}%</div>
                </div>
                <div className="kv">
                  <div className="k">Provider</div>
                  <div className="v">{item.provider}</div>
                </div>
                <div className="kv">
                  <div className="k">Generated At</div>
                  <div className="v">{formatTime(item.created_at)}</div>
                </div>
              </div>

              {itemErrors[item.id] && <ErrorBanner message={itemErrors[item.id]} />}

              <div className="toolbar">
                <label htmlFor={`comment-${item.id}`}>Review comment</label>
                <input
                  id={`comment-${item.id}`}
                  value={comments[item.id] ?? ''}
                  onChange={(e) =>
                    setComments((prev) => ({ ...prev, [item.id]: e.target.value }))
                  }
                  placeholder="optional"
                />
              </div>

              <div className="toolbar" style={{ marginBottom: 0 }}>
                <button
                  className="btn"
                  disabled={buttonsDisabled}
                  onClick={() => decide(item, 'reject')}
                >
                  {itemBusy === 'reject' ? 'Rejecting…' : 'Reject'}
                </button>
                <button
                  className="btn primary"
                  disabled={buttonsDisabled}
                  onClick={() => decide(item, 'approve')}
                >
                  {itemBusy === 'approve' ? 'Approving…' : 'Approve'}
                </button>
              </div>
            </div>
          )
        })
      )}
    </>
  )
}
