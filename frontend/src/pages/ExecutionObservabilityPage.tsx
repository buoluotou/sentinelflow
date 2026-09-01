/** Execution Observability (Phase 3.3.3.4.2): a purely read-only view of
 * the two frozen observability read models:
 *
 *     GET /executions/metrics  -> Execution Metrics
 *     GET /executions/health   -> Adapter Health (OBSERVED, not probed)
 *
 * Hard boundaries (frozen 3.3.3.4):
 * - Page load issues exactly two GETs (Promise.all) — there is no write
 *   path from this page, no execution-credential input anywhere, and
 *   ZERO action affordances (no Execute / Retry / Compensate / Approve
 *   / Reject / Run Response, not even a refresh button).
 * - The UI renders SERVER FACTS as-is: rates are shown exactly as the
 *   backend computed them (0.8 renders as 80%), never recomputed from
 *   sibling numbers; null renders as N/A, NEVER as 0%.
 * - `observed_status` is labelled "Observed Status" and captioned as a
 *   read-model verdict over recent execution facts — it is NOT a live
 *   probe ("the adapter answers right now").
 */
import { useEffect, useState } from 'react'
import { getExecutionHealth, getExecutionMetrics } from '../api/executionObservability'
import type {
  AdapterHealthRead,
  ExecutionMetricsRead,
  ObservedHealthRead,
  ObservedStatus,
} from '../types/executionObservability'
import { ErrorBanner, Loading, Panel, formatTime } from '../components/common'

/** Server rate -> display text. The rate is the SERVER's fact; this is
 * display formatting only (x100 + rounding), never a re-derivation.
 * null keeps the frozen "undefined metric" semantics: N/A, not 0%. */
function formatRate(rate: number | null): string {
  if (rate === null) return 'N/A'
  return `${Math.round(rate * 10000) / 100}%`
}

/** Verdict chip for the four frozen observed statuses. The label ALWAYS
 * carries the word "Observed" so the verdict is never misread as a
 * live liveness probe. */
export function ObservedStatusBadge({ status }: { status: ObservedStatus }) {
  const cls =
    status === 'healthy'
      ? 'low'
      : status === 'degraded'
        ? 'medium'
        : status === 'failing'
          ? 'high'
          : 'none'
  return <span className={`badge ${cls}`}>Observed: {status}</span>
}

function StatCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="stat-card">
      <div className="label">{label}</div>
      <div className="value">{value}</div>
    </div>
  )
}

function AdapterHealthCard({ health }: { health: AdapterHealthRead }) {
  return (
    <div className="stat-card" data-testid={`adapter-${health.adapter}`}>
      <div className="label">{health.adapter}</div>
      <p>
        <ObservedStatusBadge status={health.observed_status} />
      </p>
      <p>
        Recent Success Rate: {formatRate(health.window_success_rate)}
        <br />
        Recent Failed: {health.window_failed}
        <br />
        Timeout: {health.timeout_count}
        <br />
        Unavailable: {health.unavailable_count}
        <br />
        Last Execution:{' '}
        {health.last_execution_at
          ? `${formatTime(health.last_execution_at)} (${health.last_execution_state})`
          : '—'}
      </p>
    </div>
  )
}

export function ExecutionObservabilityPage() {
  const [metrics, setMetrics] = useState<ExecutionMetricsRead | null>(null)
  const [health, setHealth] = useState<ObservedHealthRead | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    // Both read models load in parallel; any failure surfaces through the
    // shared ErrorBanner — the page has no error protocol of its own.
    Promise.all([getExecutionMetrics(), getExecutionHealth()])
      .then(([m, h]) => {
        setMetrics(m)
        setHealth(h)
      })
      .catch((e: Error) => setError(e.message))
  }, [])

  return (
    <>
      <h1 className="page-title">Execution Observability</h1>

      {error && <ErrorBanner message={error} />}
      {!metrics || !health ? (
        !error && <Loading />
      ) : (
        <>
          <Panel title="Execution Metrics">
            <div className="stat-grid">
              <StatCard label="Total Executions" value={String(metrics.total_chains)} />
              <StatCard label="Succeeded" value={String(metrics.succeeded)} />
              <StatCard label="Failed" value={String(metrics.failed)} />
              <StatCard label="Guard Rejected" value={String(metrics.guard_rejected)} />
              <StatCard label="Success Rate" value={formatRate(metrics.success_rate)} />
              <StatCard
                label="Guard Rejection Rate"
                value={formatRate(metrics.guard_rejection_rate)}
              />
            </div>
          </Panel>

          <Panel title="Adapter Health">
            <p className="muted">
              Observed health — derived from recent execution facts in the
              audit log, not a live probe.
            </p>
            {Object.keys(health.adapters).length === 0 ? (
              <p className="muted">No adapter observations</p>
            ) : (
              <div className="stat-grid">
                {Object.keys(health.adapters)
                  .sort()
                  .map((name) => (
                    <AdapterHealthCard key={name} health={health.adapters[name]} />
                  ))}
              </div>
            )}
          </Panel>
        </>
      )}
    </>
  )
}
