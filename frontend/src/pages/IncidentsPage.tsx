/** Incident Queue (Step 8.4): the SOC triage list with status filter. */
import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { listIncidents } from '../api/incidents'
import type { IncidentListResponse, IncidentStatus } from '../types/incident'
import { ErrorBanner, LevelBadge, Loading, StatusBadge, formatTime } from '../components/common'

const STATUSES: Array<IncidentStatus | ''> = [
  '',
  'open',
  'in_progress',
  'resolved',
  'false_positive',
  'closed',
]
const PAGE_SIZE = 20

export function IncidentsPage() {
  const navigate = useNavigate()
  const [data, setData] = useState<IncidentListResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const [status, setStatus] = useState<IncidentStatus | ''>('')

  const load = useCallback(() => {
    setError(null)
    listIncidents({ page, size: PAGE_SIZE, status: status || undefined })
      .then(setData)
      .catch((e: Error) => setError(e.message))
  }, [page, status])

  useEffect(() => {
    load()
  }, [load])

  const pageCount = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1

  return (
    <>
      <h1 className="page-title">Incident Queue</h1>

      {error && <ErrorBanner message={error} />}
      {!data && !error ? (
        <Loading />
      ) : (
        data && (
          <>
            <div className="toolbar">
              <label htmlFor="status-filter">Status</label>
              <select
                id="status-filter"
                value={status}
                onChange={(e) => {
                  setStatus(e.target.value as IncidentStatus | '')
                  setPage(1)
                }}
              >
                {STATUSES.map((s) => (
                  <option key={s} value={s}>
                    {s === '' ? 'All' : s.replace('_', ' ')}
                  </option>
                ))}
              </select>
              <span className="muted">{data.total} incidents</span>
            </div>

            <div className="panel">
              <table className="data">
                <thead>
                  <tr>
                    <th>Title</th>
                    <th>Severity</th>
                    <th>Risk</th>
                    <th>Status</th>
                    <th>Created</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((incident) => (
                    <tr
                      key={incident.id}
                      className="clickable"
                      onClick={() => navigate(`/incidents/${incident.id}`)}
                    >
                      <td>{incident.title}</td>
                      <td>
                        <LevelBadge level={incident.severity} />
                      </td>
                      <td>{incident.risk_score}</td>
                      <td>
                        <StatusBadge status={incident.status} />
                      </td>
                      <td>{formatTime(incident.created_at)}</td>
                    </tr>
                  ))}
                  {data.items.length === 0 && (
                    <tr>
                      <td colSpan={5} className="muted">
                        No incidents match the current filter.
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
