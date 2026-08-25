/** Dashboard home page (Step 8.2): binds ONLY /dashboard/summary. */
import { useCallback, useEffect, useState } from 'react'
import { getDashboardSummary } from '../api/dashboard'
import type { DashboardSummary, RiskLevel } from '../types/dashboard'
import { ErrorBanner, Loading } from '../components/common'

const RISK_ORDER: RiskLevel[] = ['critical', 'high', 'medium', 'low']

export function DashboardPage() {
  const [data, setData] = useState<DashboardSummary | null>(null)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(() => {
    setError(null)
    getDashboardSummary()
      .then(setData)
      .catch((e: Error) => setError(e.message))
  }, [])

  useEffect(() => {
    load()
    const timer = setInterval(load, 15_000) // SOC dashboard auto-refresh
    return () => clearInterval(timer)
  }, [load])

  if (error) return <ErrorBanner message={`Dashboard unavailable: ${error}`} />
  if (!data) return <Loading />

  const maxCount = Math.max(1, ...RISK_ORDER.map((l) => data.risk_distribution[l]))

  return (
    <>
      <h1 className="page-title">Dashboard</h1>

      <div className="stat-grid">
        <div className="stat-card accent">
          <div className="label">Active Incidents</div>
          <div className="value">{data.open_incidents}</div>
        </div>
        <div className="stat-card">
          <div className="label">Today's Alerts</div>
          <div className="value">{data.today_alerts}</div>
        </div>
        <div className="stat-card">
          <div className="label">Today's Events</div>
          <div className="value">{data.today_events}</div>
        </div>
        <div className="stat-card critical">
          <div className="label">Critical</div>
          <div className="value">{data.critical_incidents}</div>
        </div>
        <div className="stat-card high">
          <div className="label">High</div>
          <div className="value">{data.high_incidents}</div>
        </div>
        <div className="stat-card medium">
          <div className="label">Medium</div>
          <div className="value">{data.medium_incidents}</div>
        </div>
      </div>

      <section className="panel">
        <h2>Risk Distribution</h2>
        {RISK_ORDER.map((level) => {
          const count = data.risk_distribution[level]
          return (
            <div className="risk-bar-row" key={level}>
              <span className={`badge ${level}`}>{level}</span>
              <div className="track">
                <div
                  className={`fill ${level}`}
                  style={{ width: `${(count / maxCount) * 100}%` }}
                />
              </div>
              <span className="count">{count}</span>
            </div>
          )
        })}
      </section>
    </>
  )
}
