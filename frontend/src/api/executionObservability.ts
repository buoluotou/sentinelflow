/** Execution observability API client.
 *
 * Read-only surface over the two observability endpoints:
 *
 * GET /api/v1/executions/metrics
 * GET /api/v1/executions/health
 *
 * Boundaries:
 * - This module exposes GET functions only — there are no write-verb
 * wrappers here, and no executor/probe call of any kind (observed
 * health is derived from execution_log server-side, never a live
 * check against any external adapter).
 * - Neither endpoint requires an execution token, so this module never
 * accepts, stores or sends auth headers.
 * - Bodies are returned as-is: the read-model types mirror the backend
 * schemas field for field; callers render facts, never recompute.
 */
import { api } from './client'
import type {
  ExecutionMetricsRead,
  ObservedHealthRead,
} from '../types/executionObservability'

/** Platform execution metrics (read model over execution_log). */
export function getExecutionMetrics(): Promise<ExecutionMetricsRead> {
  return api.get<ExecutionMetricsRead>('/executions/metrics')
}

/** Per-adapter observed health — what the recent execution facts show.
 * Not a live probe: no outbound request to any adapter ever happens. */
export function getExecutionHealth(): Promise<ObservedHealthRead> {
  return api.get<ObservedHealthRead>('/executions/health')
}
