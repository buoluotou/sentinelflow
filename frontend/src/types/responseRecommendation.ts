/** AI response-recommendation types — field-level mirror of backend
 * AIResponseRecommendationRead (Step 12.5).
 *
 * Advisory only end-to-end: every action stays a suggestion until human
 * approval (Step 13) — nothing here is ever executable. Deliberately NO
 * risk-score field: EventRisk.score stays the single official score.
 */

/** The six frozen response actions (12.1). Display-only union: the UI maps
 * them to readable labels but never invents new action semantics. */
export type ResponseAction =
  | 'block_source_ip'
  | 'isolate_host'
  | 'disable_account'
  | 'hunt_related_activity'
  | 'escalate_to_incident'
  | 'monitor_only'

export interface RecommendationItem {
  action: ResponseAction
  /** Analyst-readable string — never an executable payload. */
  target: string
  rationale: string
}

export interface AIResponseRecommendation {
  id: string
  alert_group_id: string
  provider: string
  model: string
  overall_rationale: string
  recommendations: RecommendationItem[]
  confidence: number
  created_at: string
  updated_at: string
}
