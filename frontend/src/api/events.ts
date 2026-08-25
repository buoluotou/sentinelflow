/** Events API client (list with risk-level filter + pagination, detail). */
import { api, queryString } from './client'
import type { EventDetailResponse, EventListResponse, RiskLevel } from '../types/event'

export interface EventListParams {
  page?: number
  size?: number
  level?: RiskLevel
}

export function listEvents(params: EventListParams = {}): Promise<EventListResponse> {
  const { page, size, level } = params
  return api.get<EventListResponse>(`/events${queryString({ page, size, level })}`)
}

export function getEvent(id: string): Promise<EventDetailResponse> {
  return api.get<EventDetailResponse>(`/events/${id}`)
}
