/** AI response-recommendation API client (Step 12.5): explicit-trigger
 * endpoints only.
 *
 * Mirrors the Step 11 aiRiskSummary client — same error passthrough contract:
 * backend `detail` strings (404/503/502) surface verbatim through ApiError.
 */
import { api } from './client'
import { ApiError } from './client'
import type { AIResponseRecommendation } from '../types/responseRecommendation'

/** Latest recommendation of an event, or null when none has been generated.
 *
 * The backend answers 404 both for an unknown event and for "no record yet";
 * on the event detail page the event is already loaded, so only the latter
 * is mapped to null — any other 404 surfaces as an error. Note: a record
 * with recommendations === [] is a SUCCESS (AI judged no action warranted),
 * never a null empty state.
 */
export async function getResponseRecommendation(
  eventId: string,
): Promise<AIResponseRecommendation | null> {
  try {
    return await api.get<AIResponseRecommendation>(
      `/events/${eventId}/response-recommendation`,
    )
  } catch (e) {
    if (
      e instanceof ApiError &&
      e.status === 404 &&
      e.message.includes('No response recommendation')
    ) {
      return null
    }
    throw e
  }
}

/** Trigger a new recommendation; the backend appends a history row (201). */
export function generateResponseRecommendation(
  eventId: string,
): Promise<AIResponseRecommendation> {
  return api.post<AIResponseRecommendation>(
    `/events/${eventId}/response-recommendation`,
    {},
  )
}
