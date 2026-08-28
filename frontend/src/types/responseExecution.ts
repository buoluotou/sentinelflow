/** Response-execution types — field-level mirror of backend Phase 3.1.7
 * schemas (response_execution.py).
 *
 * The client expresses Intent ONLY: identity keys + operator. action /
 * target / direction / decisions / audit clock are server-side facts —
 * the request interfaces deliberately lack those fields, and the write
 * endpoints reject unknown fields (extra="forbid").
 */

/** Body of POST /api/v1/executions — the Execute Intent, nothing more.
 * Deliberately NO action / target / direction / status / detail /
 * created_at: the server resolves the approved snapshot itself. */
export interface ExecuteIntent {
  execution_id: string
  approval_id: string
  operator: string
  comment?: string
}

/** One immutable audit row (backend ExecutionLogRowRead). */
export interface ExecutionLogRowRead {
  id: string
  execution_id: string
  approval_id: string
  decision: string
  direction: 'execute' | 'compensate'
  action: string
  target: string
  operator: string
  /** Guard reasons / dispatch echo / adapter details. NEVER contains the
   * execution token (frozen security discipline). */
  detail: Record<string, unknown>
  compensates_execution_id: string | null
  created_at: string
}

/** The 201 body of POST /executions and the GET detail body. 201 means
 * the Intent formed an execution FACT — derived_state carries the verdict
 * (succeeded / failed / guard_rejected), never an HTTP-status semantics. */
export interface ExecutionRead {
  execution_id: string
  approval_id: string
  direction: 'execute' | 'compensate'
  action: string
  target: string
  derived_state: string
  chain: string[]
  history: ExecutionLogRowRead[]
}

/** One GET /executions list entry (backend ExecutionSummaryRead). */
export interface ExecutionSummaryRead {
  execution_id: string
  approval_id: string
  direction: 'execute' | 'compensate'
  action: string
  target: string
  operator: string
  derived_state: string
  chain: string[]
  created_at: string
  last_decision_at: string
}

/** Every derivable state — the backend StateFilter vocabulary (3.1.9).
 * The server derives these via derive_execution_state(); the UI only
 * displays and filters by them, never recomputes. */
export type ExecutionDerivedState =
  | 'requested'
  | 'guard_rejected'
  | 'dispatched'
  | 'succeeded'
  | 'failed'
  | 'compensation_requested'
  | 'compensation_succeeded'
  | 'compensation_failed'

/** GET /executions query contract (3.1.9, design §10): Filter -> GET.
 * Omitted fields stay server defaults. */
export interface ExecutionListParams {
  page?: number
  size?: number
  status?: ExecutionDerivedState
  direction?: 'execute' | 'compensate'
  approval_id?: string
}

/** GET /executions paged envelope (backend ExecutionListResponse) —
 * mirrors the incidents/events list shape. */
export interface ExecutionListResponse {
  total: number
  page: number
  size: number
  items: ExecutionSummaryRead[]
}
