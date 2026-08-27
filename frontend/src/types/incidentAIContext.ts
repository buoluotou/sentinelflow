/** Incident AI context types — field-level mirror of backend
 * IncidentAIContext (Phase 2 Step 14.5).
 *
 * ONE protocol, shared semantics front-to-back: this file composes the
 * EXISTING frozen types (Steps 10–13) exactly as the backend DTO embeds
 * its Read schemas — no second AI protocol, no translated view-model.
 */
import type { AIAnalysis } from './aiAnalysis'
import type { AIRiskSummary } from './aiRiskSummary'
import type { AIResponseApproval } from './responseApproval'
import type { AIResponseRecommendation } from './responseRecommendation'

/** Mirror of backend IncidentSnapshot — read-only case header.
 * `risk_score_snapshot` is the creation-time copy of EventRisk.score;
 * the UI displays it and never recomputes or re-labels it as a live score. */
export interface IncidentSnapshot {
  id: string
  status: string
  severity: string
  risk_score_snapshot: number
}

/** Mirror of backend RecommendationWithApproval: one Step 12 recommendation
 * plus its Step 13 audit trail. `approval === null` IS the pending state —
 * a derived UI semantic, never a status sent back to the backend. */
export interface RecommendationWithApproval {
  recommendation: AIResponseRecommendation
  approval: AIResponseApproval | null
}

/** Mirror of backend IncidentAIContext: the complete AI history of one
 * incident, histories complete (never truncated) and created_at ASC. */
export interface IncidentAIContext {
  incident: IncidentSnapshot
  analyses: AIAnalysis[]
  risk_summaries: AIRiskSummary[]
  response_recommendations: RecommendationWithApproval[]
}
