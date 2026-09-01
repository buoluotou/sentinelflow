/** Execution observability types — field-level mirror of the backend
 * Phase 3.3.3 read-model schemas (metrics + observed health).
 *
 * These are READ models: the backend derives every number from
 * execution_log; the client renders them as-is and never recomputes,
 * renames or reshapes a field.
 *
 * Null semantics (frozen 3.3.3.1/3.3.3.2): a `null` rate means the
 * denominator is empty — "not enough data to define this metric".
 * The UI must render it as N/A, NEVER as 0%.
 *
 * Health semantics (frozen 3.3.3.3): `observed_status` is what the
 * execution facts SHOW over the recent window — it is NOT a live probe
 * ("the adapter answers right now"). There is deliberately no boolean
 * `healthy` field anywhere in this module.
 */

/** Frozen observed-status vocabulary (backend health.py, 3.3.3.3.1). */
export type ObservedStatus = 'healthy' | 'degraded' | 'failing' | 'unknown'

/** Mirror of backend LatencyStatsRead — adapter-run time of chains
 * that reached a terminal executor outcome (seconds; null = no data). */
export interface LatencyStatsRead {
  count: number
  average_seconds: number | null
  min_seconds: number | null
  max_seconds: number | null
}

/** Mirror of backend AdapterMetricsRead — one adapter's lifetime
 * metrics. Adapter identity is the server-recorded detail.executor
 * fact, never client-supplied. */
export interface AdapterMetricsRead {
  adapter: string
  total_chains: number
  succeeded: number
  failed: number
  guard_rejected: number
  in_flight: number
  /** null = no terminal executor chain (undefined, not 0%). */
  success_rate: number | null
  failure_classifications: Record<string, number>
}

/** Mirror of backend ExecutionMetricsRead — GET /executions/metrics
 * body. Rates keep the frozen null semantics; guard_rejected is a
 * GOVERNANCE metric and never enters the executor success/failure
 * denominator. */
export interface ExecutionMetricsRead {
  total_chains: number
  executed_chains: number
  succeeded: number
  failed: number
  guard_rejected: number
  in_flight: number
  /** succeeded / (succeeded + failed); null on an empty denominator. */
  success_rate: number | null
  executor_failure_rate: number | null
  /** guard_rejected / total chains — governance pressure indicator. */
  guard_rejection_rate: number | null
  rejections_by_source: Record<string, number>
  failure_classifications: Record<string, number>
  latency: LatencyStatsRead
  by_adapter: Record<string, AdapterMetricsRead>
}

/** Mirror of backend RecentFailureRead — one failed chain inside the
 * recent health window. */
export interface RecentFailureRead {
  execution_id: string
  /** Frozen failure-classification word, or null when absent. */
  classification: string | null
  failed_at: string
}

/** Mirror of backend AdapterHealthRead — one adapter's OBSERVED health
 * (recent window + all-time facts + last execution). */
export interface AdapterHealthRead {
  adapter: string
  /** The ONLY verdict word — never a boolean flag. */
  observed_status: ObservedStatus
  window_size: number
  window_succeeded: number
  window_failed: number
  window_success_rate: number | null
  timeout_count: number
  unavailable_count: number
  protocol_violation_count: number
  recent_failures: RecentFailureRead[]
  total_chains: number
  all_time_succeeded: number
  all_time_failed: number
  all_time_guard_rejected: number
  all_time_in_flight: number
  last_execution_at: string | null
  last_execution_state: string | null
}

/** Mirror of backend ObservedHealthRead — GET /executions/health body.
 * `generated_at` is the only wall-clock field (two identical follow-up
 * calls agree on everything else). */
export interface ObservedHealthRead {
  generated_at: string
  window_size: number
  adapters: Record<string, AdapterHealthRead>
}
