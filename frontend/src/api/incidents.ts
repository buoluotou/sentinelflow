/** Incidents API client (queue listing, detail, lifecycle transitions). */
import { api, queryString } from './client'
import type { Incident, IncidentListResponse, IncidentStatus } from '../types/incident'

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
