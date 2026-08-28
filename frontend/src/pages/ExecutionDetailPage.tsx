/** Execution detail (Phase 3.1.9): one execution's complete append-only
 * timeline + compensation relation. Strictly read-only:
 *
 *  - zero action affordances (no Execute / Approve / Reject / Retry /
 *    Compensate) — the only interactive element is the detail expander;
 *  - zero token: GET-only traffic through the shared client;
 *  - detail payloads (adapter errors / raw responses / guard reasons) are
 *    rendered as escaped JSON text — NEVER as HTML (untrusted upstream data
 *    from real Shuffle/Wazuh/TheHive adapters must not be injectable).
 */
import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getExecution, getExecutions } from '../api/responseExecution'
import type { ExecutionRead } from '../types/responseExecution'
import { ErrorBanner, Loading, Panel, formatTime } from '../components/common'
import { ExecutionStateBadge } from './ExecutionAuditPage'

export function ExecutionDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [data, setData] = useState<ExecutionRead | null>(null)
  const [error, setError] = useState<string | null>(null)
  /** The compensation chain entry for this approval (execute direction only). */
  const [compensatedBy, setCompensatedBy] = useState<string | null>(null)
  /** Row ids whose detail block is expanded (collapsed by default). */
  const [expanded, setExpanded] = useState<Record<string, boolean>>({})

  const load = useCallback(() => {
    if (!id) return
    setError(null)
    getExecution(id)
      .then(setData)
      .catch((e: Error) => setError(e.message))
  }, [id])

  useEffect(() => {
    load()
  }, [load])

  // Compensation relation discovery (read-only lookup, no new endpoint):
  // a compensation inherits the approval and is unique per approval, so the
  // filtered list answers "Compensated by" for a forward execution.
  useEffect(() => {
    if (!data || data.direction !== 'execute') return
    let cancelled = false
    getExecutions({ approval_id: data.approval_id, direction: 'compensate' })
      .then((list) => {
        if (!cancelled) setCompensatedBy(list.items[0]?.execution_id ?? null)
      })
      .catch(() => {
        /* relation lookup is best-effort; the timeline still stands alone */
      })
    return () => {
      cancelled = true
    }
  }, [data])

  if (error) {
    return (
      <>
        <p>
          <Link to="/executions">← Execution Audit</Link>
        </p>
        <ErrorBanner message={error} />
      </>
    )
  }
  if (!data) return <Loading />

  const first = data.history[0]
  const compensates =
    data.direction === 'compensate' ? first?.compensates_execution_id ?? null : null

  return (
    <>
      <p>
        <Link to="/executions">← Execution Audit</Link>
      </p>
      <h1 className="page-title">Execution {data.execution_id}</h1>

      <Panel title="Execution">
        <div className="kv-grid">
          <div className="kv">
            <div className="k">State</div>
            <div className="v">
              <ExecutionStateBadge state={data.derived_state} />
            </div>
          </div>
          <div className="kv">
            <div className="k">Action</div>
            <div className="v">{data.action}</div>
          </div>
          <div className="kv">
            <div className="k">Target</div>
            <div className="v">{data.target}</div>
          </div>
          <div className="kv">
            <div className="k">Direction</div>
            <div className="v">{data.direction}</div>
          </div>
          <div className="kv">
            <div className="k">Approval</div>
            <div className="v mono">{data.approval_id}</div>
          </div>
          <div className="kv">
            <div className="k">Execution ID</div>
            <div className="v mono">{data.execution_id}</div>
          </div>
        </div>
      </Panel>

      {(compensates || data.direction === 'execute') && (
        <Panel title="Compensation Relation">
          {compensates && (
            <p style={{ margin: 0 }}>
              Compensates:{' '}
              <Link to={`/executions/${compensates}`} className="mono">
                {compensates}
              </Link>
            </p>
          )}
          {data.direction === 'execute' && (
            <p style={{ margin: 0 }}>
              Compensated by:{' '}
              {compensatedBy ? (
                <Link to={`/executions/${compensatedBy}`} className="mono">
                  {compensatedBy}
                </Link>
              ) : (
                <span className="muted">none</span>
              )}
            </p>
          )}
        </Panel>
      )}

      <Panel title="Timeline">
        <ol className="timeline">
          {data.history.map((row) => {
            const hasDetail = Object.keys(row.detail).length > 0
            const isOpen = expanded[row.id] === true
            return (
              <li key={row.id}>
                <div>
                  <strong>{row.decision.replace(/_/g, ' ')}</strong>{' '}
                  <span className="muted">
                    by {row.operator} · {formatTime(row.created_at)}
                  </span>
                </div>
                {hasDetail && (
                  <>
                    <button
                      className="btn"
                      aria-expanded={isOpen}
                      onClick={() =>
                        setExpanded((prev) => ({ ...prev, [row.id]: !isOpen }))
                      }
                    >
                      {isOpen ? 'Hide detail' : 'Show detail'}
                    </button>
                    {isOpen && (
                      // Escaped JSON text — never HTML (untrusted upstream data).
                      <pre className="mono">{JSON.stringify(row.detail, null, 2)}</pre>
                    )}
                  </>
                )}
              </li>
            )
          })}
        </ol>
      </Panel>
    </>
  )
}
