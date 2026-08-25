/** Dashboard API client — binds the single aggregated summary endpoint. */
import { api } from './client'
import type { DashboardSummary } from '../types/dashboard'

export function getDashboardSummary(): Promise<DashboardSummary> {
  return api.get<DashboardSummary>('/dashboard/summary')
}
