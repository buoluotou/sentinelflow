/** Response-execution API client (Phase 3.1.8, frozen 3.1.7 contract).
 *
 * WRITE path: POST /executions sends the Execute Intent ONLY
 * ({ execution_id, approval_id, operator, comment? }) with the Bearer
 * EXECUTION_TOKEN passed per-call — the token is a function argument, never
 * a module/global/persistent store, so it cannot outlive the modal state.
 *
 * The 201 body is authoritative: callers render derived_state / chain /
 * history straight from the response — NO follow-up GET after POST.
 *
 * GET endpoints are read-only audit views (no token). The compensate
 * endpoint is deliberately NOT wrapped here — 3.1.8 ships execute only;
 * compensation UI belongs to a later step.
 */
import { api, queryString } from './client'
import type {
  ExecuteIntent,
  ExecutionListParams,
  ExecutionListResponse,
  ExecutionRead,
} from '../types/responseExecution'

/** Paged audit list (3.1.9 query contract): Filter -> GET. All filtering,
 * ordering (most recent activity first) and state derivation stay
 * server-side — the caller renders the envelope as-is (no token). */
export function getExecutions(
  params: ExecutionListParams = {},
): Promise<ExecutionListResponse> {
  const { page, size, status, direction, approval_id } = params
  return api.get<ExecutionListResponse>(
    `/executions${queryString({ page, size, status, direction, approval_id })}`,
  )
}

/** One execution's complete audit history (no token required). */
export function getExecution(executionId: string): Promise<ExecutionRead> {
  return api.get<ExecutionRead>(`/executions/${executionId}`)
}

/** Run one Execute Intent (201 = an execution fact exists; the verdict
 * lives in the body's derived_state). The token travels ONLY as the
 * Authorization header of this single request. */
export function executeResponse(
  intent: ExecuteIntent,
  token: string,
): Promise<ExecutionRead> {
  return api.post<ExecutionRead>('/executions', intent, {
    Authorization: `Bearer ${token}`,
  })
}
