/** Execution observability API client (Phase 3.3.3.4.1).
 *
 * READ-ONLY surface over the two frozen observability endpoints:
 *
 *     GET /api/v1/executions/metrics   (3.3.3.2)
 *     GET /api/v1/executions/health    (3.3.3.3.2)
 *
 * Hard boundaries (frozen 3.3.3.4):
 * - This module exposes GET functions ONLY — there are no write-verb
 *   wrappers here, and no executor/probe call of any kind (observed
 *   health is derived from execution_log server-side, never a live
 *   check against any external adapter).
 * - Neither endpoint requires an execution token, so this module never
 *   accepts, stores or sends auth headers.
 * - Bodies are returned as-is: the read-model types mirror the backend
 *   schemas field for field; callers render facts, never recompute.
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

/** Per-adapter OBSERVED health — what the recent execution facts show.
 * NOT a live probe: no outbound request to any adapter ever happens. */
export function getExecutionHealth(): Promise<ObservedHealthRead> {
  return api.get<ObservedHealthRead>('/executions/health')
}
