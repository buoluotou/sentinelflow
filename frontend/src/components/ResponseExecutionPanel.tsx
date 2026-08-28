/** Response Execution console (Phase 3.1.8): the FIRST UI able to trigger
 * a real execution — built deliberately more cautiously than ordinary UI.
 *
 * HARD RULE: React never re-judges permission. It decides whether to SHOW
 * the Execute button (approval.status === 'approved' AND no forward
 * execution exists yet) — it can NEVER decide whether execution is really
 * allowed. The real security boundary stays server-side: Bearer Token +
 * Server Guard + Approval + Policy + Executor.
 *
 * Frozen discipline locked here (and in the tests):
 * - GET-only on mount (existing execution status); POST happens ONLY after
 *   an explicit operator confirmation — page load fires zero POSTs
 * - the 201 body is authoritative: derived_state / chain / history render
 *   straight from the response — NO follow-up GET after POST
 * - 201 + guard_rejected is a legally formed execution FACT, rendered as
 *   status — never as an error banner (HTTP was 201, not 403)
 * - the token lives ONLY in modal-local React state (memory): never
 *   localStorage / sessionStorage / IndexedDB / URL / persistent store; it
 *   dies with the modal unmount
 * - execution_id = crypto.randomUUID(), generated ONCE per fresh Execute
 *   Intent — never derived from approval_id, never reused across intents
 * - the request body strictly mirrors the API: { execution_id, approval_id,
 *   operator, comment? } — never action / target / direction / status /
 *   detail / created_at
 * - Confirm is disabled + "Submitting…" while the request is in flight
 *   (UX guard; the server's approval_id uniqueness is the real defense)
 * - NO Retry / Compensate / Approve / Reject affordance — compensation UI
 *   belongs to a later step
 */
import { useCallback, useEffect, useRef, useState } from 'react'
import { executeResponse, getExecution, getExecutions } from '../api/responseExecution'
import { ApiError } from '../api/client'
import type { AIResponseApproval } from '../types/responseApproval'
import type { ExecuteIntent, ExecutionRead } from '../types/responseExecution'
import { ErrorBanner, formatTime } from './common'

/** Terminal-state chip: the verdict comes from the execution FACT
 * (derived_state), never from an HTTP status. */
function StateBadge({ state }: { state: string }) {
  if (state === 'succeeded') return <span className="badge low">Succeeded</span>
  if (state === 'failed') return <span className="badge high">Failed</span>
  if (state === 'guard_rejected') return <span className="badge none">Guard Rejected</span>
  return <span className="badge none">{state.replace(/_/g, ' ')}</span>
}

/** Read-only execution fact block — status + audit identity. Deliberately
 * offers no Retry / Compensate action (3.1.8 boundary). */
function ExecutionStatus({ result }: { result: ExecutionRead }) {
  const last = result.history[result.history.length - 1]
  const detail = last?.detail ?? {}
  return (
    <div className="kv-grid" style={{ marginTop: 8 }}>
      <div className="kv">
        <div className="k">Execution</div>
        <div className="v">
          <StateBadge state={result.derived_state} />
        </div>
      </div>
      <div className="kv">
        <div className="k">Execution ID</div>
        <div className="v mono">{result.execution_id}</div>
      </div>
      <div className="kv">
        <div className="k">Operator</div>
        <div className="v">{last?.operator ?? '—'}</div>
      </div>
      <div className="kv">
        <div className="k">Time</div>
        <div className="v">{last ? formatTime(last.created_at) : '—'}</div>
      </div>
      {result.derived_state === 'failed' && typeof detail.classification === 'string' && (
        <div className="kv" style={{ gridColumn: '1 / -1' }}>
          <div className="k">Classification</div>
          <div className="v">{detail.classification}</div>
        </div>
      )}
      {result.derived_state === 'guard_rejected' && (
        <div className="kv" style={{ gridColumn: '1 / -1' }}>
          <div className="k">Reason</div>
          <div className="v">
            {typeof detail.reason === 'string'
              ? detail.reason
              : typeof detail.code === 'string'
                ? detail.code
                : '—'}
          </div>
        </div>
      )}
      <div className="kv" style={{ gridColumn: '1 / -1' }}>
        <div className="k">Chain</div>
        <div className="v mono">{result.chain.join(' → ')}</div>
      </div>
    </div>
  )
}

/** Backend contract -> operator-readable submit error. 401 gets a STATIC
 * message so no credential fragment can ever reach the DOM; 404/409 show
 * the backend's stable message verbatim. */
function friendlyExecutionError(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 401) return 'Execution credentials invalid'
    if (e.status === 404) return 'Approval not found'
    return e.message
  }
  return e instanceof Error ? e.message : String(e)
}

interface ExecuteModalProps {
  approvalId: string
  onCancel: () => void
  onExecuted: (result: ExecutionRead) => void
}

/** The Token + Confirm dialog. ALL fields — including the token — are
 * local component state: closing or completing the modal unmounts it and
 * the token is gone from memory. Nothing is ever persisted. */
function ExecuteModal({ approvalId, onCancel, onExecuted }: ExecuteModalProps) {
  // ONE fresh execution identity per Execute Intent — generated when the
  // intent begins (modal open), never derived from approval_id and never
  // regenerated per click (double-clicks therefore hit the same key and
  // the server's idempotency holds even if the UI guard ever fails).
  const [executionId] = useState(() => crypto.randomUUID())
  const [operator, setOperator] = useState('')
  const [token, setToken] = useState('')
  const [comment, setComment] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // Hard in-flight gate: the state flag alone can lag one render behind a
  // same-tick double click, so a ref blocks the second submit outright.
  // (UX layer only — the server's approval_id uniqueness is the real
  // defense.)
  const inFlight = useRef(false)

  const submit = useCallback(() => {
    if (inFlight.current) return // double-click guard (UX layer only)
    const trimmedOperator = operator.trim()
    if (!trimmedOperator || !token) return
    inFlight.current = true
    setSubmitting(true)
    setError(null)
    const trimmedComment = comment.trim()
    const intent: ExecuteIntent = {
      execution_id: executionId,
      approval_id: approvalId,
      operator: trimmedOperator,
      ...(trimmedComment ? { comment: trimmedComment } : {}),
    }
    executeResponse(intent, token)
      .then(onExecuted) // 201 body is authoritative — no follow-up GET
      .catch((e: unknown) => setError(friendlyExecutionError(e)))
      .finally(() => {
        inFlight.current = false
        setSubmitting(false)
      })
  }, [operator, token, comment, executionId, approvalId, onExecuted])

  const ready = operator.trim().length > 0 && token.length > 0

  return (
    <div className="panel" style={{ marginTop: 8 }}>
      <h3>Execute Response</h3>
      <div className="toolbar">
        <label htmlFor={`exec-operator-${approvalId}`}>Operator</label>
        <input
          id={`exec-operator-${approvalId}`}
          value={operator}
          onChange={(e) => setOperator(e.target.value)}
          placeholder="ops-01"
        />
      </div>
      <div className="toolbar">
        <label htmlFor={`exec-token-${approvalId}`}>Execution Token</label>
        <input
          id={`exec-token-${approvalId}`}
          type="password"
          autoComplete="off"
          value={token}
          onChange={(e) => setToken(e.target.value)}
        />
      </div>
      <div className="toolbar">
        <label htmlFor={`exec-comment-${approvalId}`}>Comment (optional)</label>
        <input
          id={`exec-comment-${approvalId}`}
          value={comment}
          onChange={(e) => setComment(e.target.value)}
        />
      </div>
      {error && <ErrorBanner message={error} />}
      <p className="muted" style={{ marginTop: 4, marginBottom: 8 }}>
        The token is held in memory only and discarded when this dialog closes.
        The server decides whether execution is allowed — Token, Guard, Approval,
        Policy and Executor.
      </p>
      <div className="toolbar" style={{ marginBottom: 0 }}>
        <button className="btn" onClick={onCancel} disabled={submitting}>
          Cancel
        </button>
        <button
          className="btn primary"
          onClick={submit}
          disabled={!ready || submitting}
        >
          {submitting ? 'Submitting…' : 'Confirm Execute'}
        </button>
      </div>
    </div>
  )
}

/** The execution console for ONE approved recommendation. Renders nothing
 * for pending / rejected approvals — the button's presence is a display
 * decision, never a permission decision. */
export function ResponseExecutionPanel({
  approval,
}: {
  approval: AIResponseApproval | null
}) {
  const [result, setResult] = useState<ExecutionRead | null>(null)
  const [statusKnown, setStatusKnown] = useState(false)
  const [loadError, setLoadError] = useState<string | null>(null)
  const [modalOpen, setModalOpen] = useState(false)

  const approvalId = approval?.id
  useEffect(() => {
    // Effects always run (the render-time early return below can't skip
    // them), so the display gate is repeated here: pending / rejected
    // approvals fire ZERO requests.
    if (!approvalId || approval?.status !== 'approved') return
    let cancelled = false
    // Does a forward execution already exist for this approval? If so the
    // panel shows the fact instead of offering a duplicate Execute.
    getExecutions({ approval_id: approvalId })
      .then((list) => {
        const forward = list.items.find(
          (s) => s.approval_id === approvalId && s.direction === 'execute',
        )
        if (!forward) {
          if (!cancelled) setStatusKnown(true)
          return
        }
        return getExecution(forward.execution_id).then((detail) => {
          if (!cancelled) {
            setResult(detail)
            setStatusKnown(true)
          }
        })
      })
      .catch((e: unknown) => {
        if (!cancelled) setLoadError(e instanceof Error ? e.message : String(e))
      })
    return () => {
      cancelled = true
    }
  }, [approvalId, approval?.status])

  // Pending (approval === null) and rejected never see any execution UI.
  if (!approval || approval.status !== 'approved') return null

  const handleExecuted = (executed: ExecutionRead) => {
    setResult(executed)
    setModalOpen(false) // unmounts the modal — the token dies here
  }

  return (
    <>
      {loadError && <ErrorBanner message={loadError} />}
      {result ? (
        <ExecutionStatus result={result} />
      ) : statusKnown ? (
        modalOpen ? (
          <ExecuteModal
            approvalId={approval.id}
            onCancel={() => setModalOpen(false)}
            onExecuted={handleExecuted}
          />
        ) : (
          <div className="toolbar" style={{ marginTop: 8, marginBottom: 0 }}>
            <button className="btn primary" onClick={() => setModalOpen(true)}>
              Execute
            </button>
            <span className="muted">
              Approved recommendation — execution still requires the server token
              and passes every server guard.
            </span>
          </div>
        )
      ) : (
        !loadError && (
          <p className="muted" style={{ marginTop: 8, marginBottom: 0 }}>
            Loading execution status…
          </p>
        )
      )}
    </>
  )
}
