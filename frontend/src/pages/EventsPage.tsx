/** Events queue (Step 8.3): list with risk-level filter + pagination. */
import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { listEvents } from '../api/events'
import type { EventListResponse, RiskLevel } from '../types/event'
import { ErrorBanner, LevelBadge, Loading, formatTime } from '../components/common'

const LEVELS: Array<RiskLevel | ''> = ['', 'critical', 'high', 'medium', 'low']
const PAGE_SIZE = 20

export function EventsPage() {
  const navigate = useNavigate()
  const [data, setData] = useState<EventListResponse | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [page, setPage] = useState(1)
  const [level, setLevel] = useState<RiskLevel | ''>('')

  const load = useCallback(() => {
    setError(null)
    listEvents({ page, size: PAGE_SIZE, level: level || undefined })
      .then(setData)
      .catch((e: Error) => setError(e.message))
  }, [page, level])

  useEffect(() => {
    load()
  }, [load])

  const pageCount = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1

  return (
    <>
      <h1 className="page-title">Events</h1>

      {error && <ErrorBanner message={error} />}
      {!data && !error ? (
        <Loading />
      ) : (
        data && (
          <>
            <div className="toolbar">
              <label htmlFor="level-filter">Risk level</label>
              <select
                id="level-filter"
                value={level}
                onChange={(e) => {
                  setLevel(e.target.value as RiskLevel | '')
                  setPage(1)
                }}
              >
                {LEVELS.map((l) => (
                  <option key={l} value={l}>
                    {l === '' ? 'All' : l}
                  </option>
                ))}
              </select>
              <span className="muted">{data.total} events</span>
            </div>

            <div className="panel">
              <table className="data">
                <thead>
                  <tr>
                    <th>Event</th>
                    <th>Severity</th>
                    <th>Risk</th>
                    <th>Level</th>
                    <th>Alerts</th>
                    <th>First Seen</th>
                    <th>Last Seen</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((event) => (
                    <tr
                      key={event.id}
                      className="clickable"
                      onClick={() => navigate(`/events/${event.id}`)}
                    >
                      <td>
                        <div>{event.title}</div>
                        <div className="muted" style={{ fontSize: 12 }}>
                          {event.category}
                        </div>
                      </td>
                      <td>
                        <LevelBadge level={event.severity} />
                      </td>
                      <td>{event.risk_score ?? '—'}</td>
                      <td>
                        <LevelBadge level={event.risk_level} />
                      </td>
                      <td>{event.alert_count}</td>
                      <td>{formatTime(event.first_seen)}</td>
                      <td>{formatTime(event.last_seen)}</td>
                      <td>{event.status}</td>
                    </tr>
                  ))}
                  {data.items.length === 0 && (
                    <tr>
                      <td colSpan={8} className="muted">
                        No events match the current filter.
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
