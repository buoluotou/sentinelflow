/**
 * TypeScript mirror of the Events API schemas (Phase 1 Step 4.4 / 5.4).
 * Backend serialises UUID/datetime as strings; keep them as strings here.
 */

export type EventSeverity = 'low' | 'medium' | 'high' | 'critical'
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical'

export interface EventListItem {
  id: string
  title: string
  category: string
  severity: string
  status: string
  alert_count: number
  first_seen: string
  last_seen: string
  /** Current risk snapshot; null for legacy events without a risk record. */
  risk_score: number | null
  risk_level: string | null
}

export interface EventListResponse {
  total: number
  page: number
  size: number
  items: EventListItem[]
}

export interface EventAlertItem {
  id: string
  source: string
  event_type: string
  severity: string
  title: string | null
  host_name: string | null
  source_ip: string | null
  created_at: string
}

export interface EventInfo {
  id: string
  fingerprint: string
  title: string
  category: string
  severity: string
  status: string
  alert_count: number
  first_seen: string
  last_seen: string
  created_at: string
  updated_at: string
}

export interface RiskFactorItem {
  name: string
  score: number
  reason: string
}

export interface EventRiskDetail {
  score: number
  level: string
  factors: RiskFactorItem[]
  updated_at: string
}

export interface EventDetailResponse {
  event: EventInfo
  alerts: EventAlertItem[]
  risk: EventRiskDetail | null
}
