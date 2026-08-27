/** Incident detail (Step 8.4): case record + explicit lifecycle actions.
 *
 * The buttons mirror the backend's frozen ALLOWED_TRANSITIONS matrix for
 * display purposes only — validity is still decided by the service-layer
 * state machine (an invalid move surfaces as a 409 banner, never silently).
 */
import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getIncident, updateIncidentStatus } from '../api/incidents'
import type { Incident, IncidentStatus } from '../types/incident'
import { IncidentAIContextPanel } from '../components/IncidentAIContextPanel'
import { ErrorBanner, LevelBadge, Loading, Panel, StatusBadge, formatTime } from '../components/common'

const TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  open: ['in_progress', 'false_positive', 'closed'],
  in_progress: ['resolved', 'false_positive', 'closed'],
  resolved: ['closed'],
  false_positive: ['closed'],
  closed: [],
}

const ACTION_LABELS: Record<IncidentStatus, string> = {
  open: 'Open',
  in_progress: 'Start Investigation',
  resolved: 'Resolve',
  false_positive: 'Mark False Positive',
  closed: 'Close',
}

export function IncidentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [data, setData] = useState<Incident | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  const load = useCallback(() => {
    if (!id) return
    setError(null)
    getIncident(id)
      .then(setData)
      .catch((e: Error) => setError(e.message))
  }, [id])

  useEffect(() => {
    load()
  }, [load])

  async function transition(target: IncidentStatus) {
    if (!data) return
    setBusy(true)
    setActionError(null)
    try {
      setData(await updateIncidentStatus(data.id, target))
    } catch (e) {
      setActionError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  if (error) return <ErrorBanner message={error} />
  if (!data) return <Loading />

  const actions = TRANSITIONS[data.status]

  return (
    <>
      <p>
        <Link to="/incidents">← Incident Queue</Link>
      </p>
      <h1 className="page-title">{data.title}</h1>

      {actionError && <ErrorBanner message={actionError} />}

      <Panel title="Lifecycle Actions">
        {actions.length > 0 ? (
          <div className="toolbar" style={{ marginBottom: 0 }}>
            {actions.map((target) => (
              <button
                key={target}
                className={`btn ${target === 'closed' ? 'danger' : 'primary'}`}
                disabled={busy}
                onClick={() => transition(target)}
              >
                {ACTION_LABELS[target]}
              </button>
            ))}
          </div>
        ) : (
          <p className="muted" style={{ margin: 0 }}>
            This incident is closed — no further transitions are allowed.
          </p>
        )}
      </Panel>

      <Panel title="Case Record">
        <div className="kv-grid">
          <div className="kv">
            <div className="k">Status</div>
            <div className="v">
              <StatusBadge status={data.status} />
            </div>
          </div>
          <div className="kv">
            <div className="k">Severity</div>
            <div className="v">
              <LevelBadge level={data.severity} />
            </div>
          </div>
          <div className="kv">
            <div className="k">Risk Score (snapshot)</div>
            <div className="v">{data.risk_score}</div>
          </div>
          <div className="kv">
            <div className="k">Disposition</div>
            <div className="v">{data.disposition ?? '—'}</div>
          </div>
          <div className="kv">
            <div className="k">Created</div>
            <div className="v">{formatTime(data.created_at)}</div>
          </div>
          <div className="kv">
            <div className="k">Resolved</div>
            <div className="v">{formatTime(data.resolved_at)}</div>
          </div>
          <div className="kv">
            <div className="k">Closed</div>
            <div className="v">{formatTime(data.closed_at)}</div>
          </div>
          <div className="kv">
            <div className="k">Source Event</div>
            <div className="v">
              <Link to={`/events/${data.alert_group_id}`} className="mono">
                {data.alert_group_id}
              </Link>
            </div>
          </div>
          {data.description && (
            <div className="kv" style={{ gridColumn: '1 / -1' }}>
              <div className="k">Description</div>
              <div className="v">{data.description}</div>
            </div>
          )}
        </div>
      </Panel>

      {/* Step 14.5: read-only AI case context — observe/review/audit only,
          never decide/execute (the Approval Queue owns decisions). */}
      <IncidentAIContextPanel incidentId={data.id} />
    </>
  )
}
