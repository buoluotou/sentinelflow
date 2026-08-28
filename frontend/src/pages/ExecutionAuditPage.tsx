/** Execution Audit (Phase 3.1.9): read-only audit history over execution_log.
 *
 * Filter -> GET only: status / direction / approval_id / page travel as query
 * parameters and the paged envelope renders as-is. derived_state is a server
 * fact from derive_execution_state() — this page never re-derives state, and
 * it carries zero action affordances (no Execute / Approve / Reject / Retry /
 * Compensate). Token never participates: the shared client attaches no
 * Authorization header to GETs.
 */
import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getExecutions } from '../api/responseExecution'
import type {
  ExecutionDerivedState,
  ExecutionListResponse,
} from '../types/responseExecution'
import { ErrorBanner, Loading, formatTime } from '../components/common'

/** Backend StateFilter vocabulary — the 8 derivable states (frozen). */
const STATES: ExecutionDerivedState[] = [
  'requested',
  'guard_rejected',
  'dispatched',
  'succeeded',
  'failed',
  'compensation_requested',
  'compensation_succeeded',
  'compensation_failed',
]
const DIRECTIONS: Array<'execute' | 'compensate'> = ['execute', 'compensate']
const PAGE_SIZE = 20
const UUID_RE =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** Verdict chip — same semantics as the 3.1.8 console: the state is an
 * execution FACT, rendered as status (never as an error). */
export function ExecutionStateBadge({ state }: { state: string }) {
  if (state === 'succeeded') return <span className="badge low">Succeeded</span>
  if (state === 'failed') return <span className="badge high">Failed</span>
  if (state === 'guard_rejected') return <span className="badge none">Guard Rejected</span>
  return <span className="badge none">{state.replace(/_/g, ' ')}</span>
}

export function ExecutionAuditPage() {
  const navigate = useNavigate()
  const [data, setData] = useState<ExecutionListResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const [status, setStatus] = useState<ExecutionDerivedState | ''>('')
  const [direction, setDirection] = useState<'execute' | 'compensate' | ''>('')
  const [approvalInput, setApprovalInput] = useState('')

  // A malformed approval_id would 422 server-side on every keystroke; the
  // filter is applied only once the input is well-formed (query-shaping,
  // not state derivation).
  const approvalId = UUID_RE.test(approvalInput.trim())
    ? approvalInput.trim()
    : undefined

  const load = useCallback(() => {
    setError(null)
    getExecutions({
      page,
      size: PAGE_SIZE,
      status: status || undefined,
      direction: direction || undefined,
      approval_id: approvalId,
    })
      .then(setData)
      .catch((e: Error) => setError(e.message))
  }, [page, status, direction, approvalId])

  useEffect(() => {
    load()
  }, [load])

  const pageCount = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1

  return (
    <>
      <h1 className="page-title">Execution Audit</h1>

      {error && <ErrorBanner message={error} />}
      {!data && !error ? (
        <Loading />
      ) : (
        data && (
          <>
            <div className="toolbar">
              <label htmlFor="state-filter">State</label>
              <select
                id="state-filter"
                value={status}
                onChange={(e) => {
                  setStatus(e.target.value as ExecutionDerivedState | '')
                  setPage(1)
                }}
              >
                <option value="">All</option>
                {STATES.map((s) => (
                  <option key={s} value={s}>
                    {s.replace(/_/g, ' ')}
                  </option>
                ))}
              </select>

              <label htmlFor="direction-filter">Direction</label>
              <select
                id="direction-filter"
                value={direction}
                onChange={(e) => {
                  setDirection(e.target.value as 'execute' | 'compensate' | '')
                  setPage(1)
                }}
              >
                <option value="">All</option>
                {DIRECTIONS.map((d) => (
                  <option key={d} value={d}>
                    {d}
                  </option>
                ))}
              </select>

              <label htmlFor="approval-filter">Approval ID</label>
              <input
                id="approval-filter"
                type="text"
                placeholder="approval uuid"
                value={approvalInput}
                onChange={(e) => {
                  setApprovalInput(e.target.value)
                  setPage(1)
                }}
              />
              <span className="muted">{data.total} executions</span>
            </div>

            <div className="panel">
              <table className="data">
                <thead>
                  <tr>
                    <th>Execution ID</th>
                    <th>State</th>
                    <th>Action</th>
                    <th>Target</th>
                    <th>Operator</th>
                    <th>Approval</th>
                    <th>Direction</th>
                    <th>Last Activity</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <tr
                      key={item.execution_id}
                      className="clickable"
                      onClick={() => navigate(`/executions/${item.execution_id}`)}
                    >
                      <td className="mono">{item.execution_id}</td>
                      <td>
                        <ExecutionStateBadge state={item.derived_state} />
                      </td>
                      <td>{item.action}</td>
                      <td>{item.target}</td>
                      <td>{item.operator}</td>
                      <td className="mono">{item.approval_id}</td>
                      <td>{item.direction}</td>
                      <td>{formatTime(item.last_decision_at)}</td>
                    </tr>
                  ))}
                  {data.items.length === 0 && (
                    <tr>
                      <td colSpan={8} className="muted">
                        No executions match the current filter.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>

            <div className="pager">
              <button
                className="btn"
                disabled={page <= 1}
                onClick={() => setPage((p) => p - 1)}
              >
                ← Prev
              </button>
              <span>
                Page {data.page} / {pageCount}
              </span>
              <button
                className="btn"
                disabled={page >= pageCount}
                onClick={() => setPage((p) => p + 1)}
              >
                Next →
              </button>
            </div>
          </>
        )
      )}
    </>
  )
}
