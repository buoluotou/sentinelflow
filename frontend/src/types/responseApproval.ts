/** Approval-queue types — field-level mirror of the backend approval schemas.
 *
 * The queue is a backend projection: pending == recommendation with no
 * approval row. The frontend never computes pending itself, never re-sorts
 * (backend ordering is created_at ASC, id ASC) and never sends reviewed_at —
 * the server stamps the audit clock.
 */
import type { RecommendationItem } from './responseRecommendation'

/** One Approval Queue entry (backend PendingApprovalRead). */
export interface PendingApproval {
  /** The recommendation id — decisions POST against this id. */
  id: string
  event_id: string
  event_title: string
  provider: string
  model: string
  overall_rationale: string
  recommendations: RecommendationItem[]
  confidence: number
  created_at: string
}

/** Body of POST .../approve and .../reject. No reviewed_at:
 * the backend rejects unknown fields (extra="forbid") and stamps its own
 * server clock — a client can never backdate the audit trail. */
export interface ApprovalDecision {
  reviewer: string
  review_comment?: string | null
}

/** One recorded human decision — field-level mirror of backend
 * AIResponseApprovalRead.
 *
 * INSERT-only audit record: status is a terminal decision. "pending" never
 * appears here — it is the derived state of a recommendation whose approval
 * field is null, computed nowhere and stored nowhere. */
export interface AIResponseApproval {
  id: string
  recommendation_id: string
  status: 'approved' | 'rejected'
  reviewer: string
  reviewed_at: string
  review_comment: string | null
  created_at: string
  updated_at: string
}
