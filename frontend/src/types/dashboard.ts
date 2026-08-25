/**
 * TypeScript mirror of GET /api/v1/dashboard/summary (Phase 1 Step 7.5).
 *
 * Field-for-field copy of the backend schema — the console never derives
 * these numbers itself; the backend is the single source of truth.
 */

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low'

export interface RiskDistribution {
  critical: number
  high: number
  medium: number
  low: number
}

export interface DashboardSummary {
  /** Active cases only: status in (open, in_progress). */
  open_incidents: number
  /** Severity breakdown of the active cases. */
  critical_incidents: number
  high_incidents: number
  medium_incidents: number
  /** Alerts created since today 00:00 UTC. */
  today_alerts: number
  /** Events created since today 00:00 UTC. */
  today_events: number
  /** Current EventRisk.level over all events. */
  risk_distribution: RiskDistribution
}
