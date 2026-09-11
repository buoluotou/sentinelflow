/** AI risk-summary types — field-level mirror of backend AIRiskSummaryRead.
 *
 * There is no risk-score field: EventRisk.score stays the single official
 * score; the AI summary only explains, compresses and prioritises.
 */

export type AnalystPriority = 'low' | 'medium' | 'high' | 'critical'

export interface AIRiskSummary {
  id: string
  alert_group_id: string
  provider: string
  model: string
  summary: string
  key_findings: string[]
  risk_drivers: string[]
  analyst_priority: AnalystPriority
  confidence: number
  created_at: string
  updated_at: string
}
