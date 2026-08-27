/** Approval-queue types — field-level mirror of backend Step 13.3 schemas.
 *
 * The queue is a backend projection: pending == recommendation with NO
 * approval row. The frontend never computes pending itself, never re-sorts
 * (backend freezes created_at ASC, id ASC) and never sends reviewed_at —
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

/** Body of POST .../approve and .../reject. Deliberately NO reviewed_at:
 * the backend rejects unknown fields (extra="forbid") and stamps its own
 * server clock — a client can never backdate the audit trail. */
export interface ApprovalDecision {
  reviewer: string
  review_comment?: string | null
}
