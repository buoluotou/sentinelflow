/**
 * TypeScript mirror of the Incident API schemas (Phase 1 Step 7.3).
 */

export type IncidentStatus =
  | 'open'
  | 'in_progress'
  | 'resolved'
  | 'false_positive'
  | 'closed'

export interface Incident {
  id: string
  alert_group_id: string
  title: string
  description: string | null
  severity: string
  /** Snapshot copied from EventRisk when the case was created. */
  risk_score: number
  status: IncidentStatus
  disposition: string | null
  created_at: string
  updated_at: string
  resolved_at: string | null
  closed_at: string | null
}

export interface IncidentListResponse {
  total: number
  page: number
  size: number
  items: Incident[]
}
