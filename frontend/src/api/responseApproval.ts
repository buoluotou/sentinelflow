/** Approval-queue API client (Step 13.5).
 *
 * Consumes the frozen Step 13.3 contract: GET /approvals returns the
 * backend-projected pending queue (rendered as-is, never re-sorted), and
 * approve/reject POST { reviewer, review_comment } only — reviewed_at is
 * never sent (the server stamps it; extra fields are rejected upstream).
 */
import { api } from './client'
import type {
  AIResponseApproval,
  ApprovalDecision,
  PendingApproval,
} from '../types/responseApproval'

/** The Approval Queue: pending recommendations, oldest first (backend
 * ordering). 200 + [] is the normal "nothing to review" state. */
export function getApprovalQueue(): Promise<PendingApproval[]> {
  return api.get<PendingApproval[]>('/approvals')
}

/** Record a human APPROVE decision (201). Records only — executes nothing.
 * Resolves to the persisted decision (backend AIResponseApprovalRead). */
export function approveRecommendation(
  recommendationId: string,
  decision: ApprovalDecision,
): Promise<AIResponseApproval> {
  return api.post<AIResponseApproval>(
    `/response-recommendations/${recommendationId}/approve`,
    decision,
  )
}

/** Record a human REJECT decision (201). Records only — executes nothing.
 * Resolves to the persisted decision (backend AIResponseApprovalRead). */
export function rejectRecommendation(
  recommendationId: string,
  decision: ApprovalDecision,
): Promise<AIResponseApproval> {
  return api.post<AIResponseApproval>(
    `/response-recommendations/${recommendationId}/reject`,
    decision,
  )
}
