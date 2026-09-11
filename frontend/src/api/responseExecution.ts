/** Response-execution API client.
 *
 * Write path: POST /executions sends the Execute Intent only
 * ({ execution_id, approval_id, operator, comment? }) with the Bearer
 * EXECUTION_TOKEN passed per-call — the token is a function argument, never
 * a module/global/persistent store, so it cannot outlive the modal state.
 *
 * The 201 body is authoritative: callers render derived_state / chain /
 * history straight from the response — no follow-up GET after POST.
 *
 * GET endpoints are read-only audit views (no token). The compensate
 * endpoint is not wrapped here: this client covers execute only, and
 * compensation UI is not part of it.
 */
import { api, queryString } from './client'
import type {
  ExecuteIntent,
  ExecutionListParams,
  ExecutionListResponse,
  ExecutionRead,
} from '../types/responseExecution'

/** Paged audit list (filter params -> GET). All filtering,
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
 * lives in the body's derived_state). The token travels only as the
 * Authorization header of this single request. */
export function executeResponse(
  intent: ExecuteIntent,
  token: string,
): Promise<ExecutionRead> {
  return api.post<ExecutionRead>('/executions', intent, {
    Authorization: `Bearer ${token}`,
  })
}
