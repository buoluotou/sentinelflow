/** AI risk-summary API client (Step 11.6): explicit-trigger endpoints only.
 *
 * Mirrors the Step 10 aiAnalysis client — same error passthrough contract:
 * backend `detail` strings (404/503/502) surface verbatim through ApiError.
 */
import { api } from './client'
import { ApiError } from './client'
import type { AIRiskSummary } from '../types/aiRiskSummary'

/** Latest risk summary of an event, or null when none has been generated yet.
 *
 * The backend answers 404 both for an unknown event and for "no summary yet";
 * on the event detail page the event is already loaded, so only the latter is
 * mapped to null — any other 404 surfaces as an error.
 */
export async function getRiskSummary(eventId: string): Promise<AIRiskSummary | null> {
  try {
    return await api.get<AIRiskSummary>(`/events/${eventId}/ai-risk-summary`)
  } catch (e) {
    if (e instanceof ApiError && e.status === 404 && e.message.includes('No AI risk summary')) {
      return null
    }
    throw e
  }
}

/** Trigger a new summary; the backend appends a history row (201). */
export function generateRiskSummary(eventId: string): Promise<AIRiskSummary> {
  return api.post<AIRiskSummary>(`/events/${eventId}/ai-risk-summary`, {})
}
