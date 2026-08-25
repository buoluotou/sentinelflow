/** AI analysis API client (Step 10.7): explicit-trigger endpoints only. */
import { api } from './client'
import { ApiError } from './client'
import type { AIAnalysis } from '../types/aiAnalysis'

/** Latest analysis for an event, or null when none has been recorded yet.
 *
 * The backend answers 404 both for an unknown event and for "no analysis
 * yet"; on this page the event is already loaded, so only the latter is
 * mapped to null — any other 404 surfaces as an error.
 */
export async function getLatestAnalysis(eventId: string): Promise<AIAnalysis | null> {
  try {
    return await api.get<AIAnalysis>(`/events/${eventId}/ai-analysis`)
  } catch (e) {
    if (e instanceof ApiError && e.status === 404 && e.message.includes('No AI analysis')) {
      return null
    }
    throw e
  }
}

/** Trigger a new analysis; the backend appends a history row (201). */
export function createAnalysis(eventId: string): Promise<AIAnalysis> {
  return api.post<AIAnalysis>(`/events/${eventId}/ai-analysis`, {})
}
