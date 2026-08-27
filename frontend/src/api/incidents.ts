/** Incidents API client (queue listing, detail, lifecycle transitions). */
import { api, queryString } from './client'
import type { Incident, IncidentListResponse, IncidentStatus } from '../types/incident'
import type { IncidentAIContext } from '../types/incidentAIContext'

export interface IncidentListParams {
  page?: number
  size?: number
  status?: IncidentStatus
}

export function listIncidents(params: IncidentListParams = {}): Promise<IncidentListResponse> {
  const { page, size, status } = params
  return api.get<IncidentListResponse>(`/incidents${queryString({ page, size, status })}`)
}

export function getIncident(id: string): Promise<Incident> {
  return api.get<Incident>(`/incidents/${id}`)
}

/**
 * Request a lifecycle move; the backend state machine decides validity.
 * Invalid moves reject with ApiError(409, "Invalid incident status
 * transition: {from} -> {to}").
 */
export function updateIncidentStatus(id: string, status: IncidentStatus): Promise<Incident> {
  return api.patch<Incident>(`/incidents/${id}/status`, { status })
}

/**
 * The complete read-only AI history of one incident (Step 14.3 endpoint).
 * GET only — this client never generates AI data, never approves/rejects
 * and never executes anything; unknown incidents reject with ApiError(404).
 */
export function getIncidentAIContext(id: string): Promise<IncidentAIContext> {
  return api.get<IncidentAIContext>(`/incidents/${id}/ai-context`)
}
