/** Event detail (Step 8.3): fingerprint, risk factor breakdown, evidence.
 * Step 10.7 adds the AI Alert Explanation panel (display + explicit trigger).
 * Step 11.6 adds the AI Risk Summary panel (display + explicit trigger).
 * Step 12.5 adds the Response Recommendation panel (advisory only — display +
 * explicit trigger, never an executor).
 */
import { useCallback, useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { getEvent } from '../api/events'
import type { EventDetailResponse } from '../types/event'
import { AiAnalysisPanel } from '../components/AiAnalysisPanel'
import { RiskSummaryPanel } from '../components/RiskSummaryPanel'
import { ResponseRecommendationPanel } from '../components/ResponseRecommendationPanel'
import { ErrorBanner, LevelBadge, Loading, Panel, formatTime } from '../components/common'

export function EventDetailPage() {
  const { id } = useParams<{ id: string }>()
  const [data, setData] = useState<EventDetailResponse | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    if (!id) return
    setError(null)
    getEvent(id)
      .then(setData)
      .catch((e: Error) => setError(e.message))
  }, [id])

  useEffect(() => {
    load()
  }, [load])

  if (error) return <ErrorBanner message={error} />
  if (!data) return <Loading />

  const { event, alerts, risk } = data

  return (
    <>
      <p>
        <Link to="/events">← Events</Link>
      </p>
      <h1 className="page-title">{event.title}</h1>

      <Panel title="Event">
        <div className="kv-grid">
          <div className="kv">
            <div className="k">Severity</div>
            <div className="v">
              <LevelBadge level={event.severity} />
            </div>
          </div>
          <div className="kv">
            <div className="k">Category</div>
            <div className="v">{event.category}</div>
          </div>
          <div className="kv">
            <div className="k">Status</div>
            <div className="v">{event.status}</div>
          </div>
          <div className="kv">
            <div className="k">Alert Count</div>
            <div className="v">{event.alert_count}</div>
          </div>
          <div className="kv">
            <div className="k">First Seen</div>
            <div className="v">{formatTime(event.first_seen)}</div>
          </div>
          <div className="kv">
            <div className="k">Last Seen</div>
            <div className="v">{formatTime(event.last_seen)}</div>
          </div>
          <div className="kv" style={{ gridColumn: '1 / -1' }}>
            <div className="k">Fingerprint</div>
            <div className="v mono">{event.fingerprint}</div>
          </div>
        </div>
      </Panel>

      {risk ? (
        <Panel title={`Risk Assessment — ${risk.score} / ${risk.level}`}>
          <table className="data">
            <thead>
              <tr>
                <th>Factor</th>
                <th>Score</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {risk.factors.map((factor) => (
                <tr key={factor.name}>
                  <td>{factor.name}</td>
                  <td>+{factor.score}</td>
                  <td className="muted">{factor.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted" style={{ marginTop: 8, marginBottom: 0 }}>
            Last recalculated {formatTime(risk.updated_at)}
          </p>
        </Panel>
      ) : (
        <Panel title="Risk Assessment">
          <p className="muted" style={{ margin: 0 }}>
            No risk assessment recorded for this event.
          </p>
        </Panel>
      )}

      {id && <AiAnalysisPanel eventId={id} />}

      {id && <RiskSummaryPanel eventId={id} />}

      {id && <ResponseRecommendationPanel eventId={id} />}

      <Panel title={`Alert Evidence (${alerts.length})`}>
        <table className="data">
          <thead>
            <tr>
              <th>Time</th>
              <th>Source</th>
              <th>Type</th>
              <th>Severity</th>
              <th>Host</th>
              <th>Source IP</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert) => (
              <tr key={alert.id}>
                <td>{formatTime(alert.created_at)}</td>
                <td>{alert.source}</td>
                <td>{alert.event_type}</td>
                <td>
                  <LevelBadge level={alert.severity} />
                </td>
                <td>{alert.host_name ?? '—'}</td>
                <td className="mono">{alert.source_ip ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </Panel>
    </>
  )
}
