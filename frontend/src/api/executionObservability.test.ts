/** Execution observability API client tests (Phase 3.3.3.4.1).
 *
 * Locks the read-only boundary of the frontend observability layer:
 *   A. both functions hit exactly the two frozen GET endpoints
 *   B. every request is a GET with NO Authorization header (no token)
 *   C. bodies pass through verbatim — null rates stay null (the UI's
 *      N/A contract), never coerced to 0
 *   D. backend errors surface as ApiError
 *   E. module-level source locks: no POST / PATCH / PUT / DELETE, no
 *      Authorization, no probe/executor vocabulary in the client
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ApiError } from './client'
import { getExecutionHealth, getExecutionMetrics } from './executionObservability'
// Vite ?raw import: the client's source text, for the structural lock
// below (no node fs in the browser tsconfig).
import clientSource from './executionObservability.ts?raw'

const METRICS_URL = '/api/v1/executions/metrics'
const HEALTH_URL = '/api/v1/executions/health'

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

type FetchHandler = (url: string, init?: RequestInit) => Response

function routeFetch(handler: FetchHandler) {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) =>
    handler(String(input), init),
  )
  vi.stubGlobal('fetch', fn)
  return fn
}

function metricsBody(overrides: Record<string, unknown> = {}) {
  return {
    total_chains: 0,
    executed_chains: 0,
    succeeded: 0,
    failed: 0,
    guard_rejected: 0,
    in_flight: 0,
    success_rate: null,
    executor_failure_rate: null,
    guard_rejection_rate: null,
    rejections_by_source: {},
    failure_classifications: {},
    latency: {
      count: 0,
      average_seconds: null,
      min_seconds: null,
      max_seconds: null,
    },
    by_adapter: {},
    ...overrides,
  }
}

function healthBody(overrides: Record<string, unknown> = {}) {
  return {
    generated_at: '2026-09-01T12:00:00Z',
    window_size: 20,
    adapters: {},
    ...overrides,
  }
}

describe('execution observability api client', () => {
  beforeEach(() => {
    vi.unstubAllGlobals()
  })
  afterEach(() => {
    vi.unstubAllGlobals()
  })

  // ---------------------------------------------------------------- A+B
  it('getExecutionMetrics: GET /executions/metrics, no Authorization', async () => {
    const fn = routeFetch(() => json(200, metricsBody()))
    await getExecutionMetrics()
    expect(fn).toHaveBeenCalledTimes(1)
    const [url, init] = fn.mock.calls[0]
    expect(String(url)).toBe(METRICS_URL)
    expect((init?.method ?? 'GET').toUpperCase()).toBe('GET')
    const headers = (init?.headers ?? {}) as Record<string, string>
    expect(headers.Authorization).toBeUndefined()
  })

  it('getExecutionHealth: GET /executions/health, no Authorization', async () => {
    const fn = routeFetch(() => json(200, healthBody()))
    await getExecutionHealth()
    expect(fn).toHaveBeenCalledTimes(1)
    const [url, init] = fn.mock.calls[0]
    expect(String(url)).toBe(HEALTH_URL)
    expect((init?.method ?? 'GET').toUpperCase()).toBe('GET')
    const headers = (init?.headers ?? {}) as Record<string, string>
    expect(headers.Authorization).toBeUndefined()
  })

  // ---------------------------------------------------------------- C
  it('passes the metrics body through verbatim — null rates stay null', async () => {
    routeFetch(() => json(200, metricsBody()))
    const body = await getExecutionMetrics()
    // The frozen "undefined metric" semantics must survive the client:
    // null is N/A, never coerced to 0.
    expect(body.success_rate).toBeNull()
    expect(body.executor_failure_rate).toBeNull()
    expect(body.guard_rejection_rate).toBeNull()
    expect(body.latency.average_seconds).toBeNull()
    expect(body.by_adapter).toEqual({})
  })

  it('passes populated metrics through without reshaping', async () => {
    const populated = metricsBody({
      total_chains: 10,
      executed_chains: 8,
      succeeded: 3,
      failed: 5,
      guard_rejected: 2,
      success_rate: 0.375,
      executor_failure_rate: 0.625,
      guard_rejection_rate: 0.2,
      rejections_by_source: { policy: 1, guard: 1 },
      failure_classifications: { timeout: 3, adapter_error: 1, protocol_violation: 1 },
      by_adapter: {
        mock: {
          adapter: 'mock',
          total_chains: 5,
          succeeded: 3,
          failed: 0,
          guard_rejected: 2,
          in_flight: 0,
          success_rate: 1.0,
          failure_classifications: {},
        },
      },
    })
    routeFetch(() => json(200, populated))
    const body = await getExecutionMetrics()
    expect(body).toEqual(populated)
  })

  it('passes the health body through — observed_status untouched', async () => {
    const populated = healthBody({
      adapters: {
        mock: {
          adapter: 'mock',
          observed_status: 'healthy',
          window_size: 20,
          window_succeeded: 20,
          window_failed: 0,
          window_success_rate: 1.0,
          timeout_count: 0,
          unavailable_count: 0,
          protocol_violation_count: 0,
          recent_failures: [],
          total_chains: 20,
          all_time_succeeded: 20,
          all_time_failed: 0,
          all_time_guard_rejected: 0,
          all_time_in_flight: 0,
          last_execution_at: '2026-09-01T11:59:00Z',
          last_execution_state: 'succeeded',
        },
        shuffle: {
          adapter: 'shuffle',
          observed_status: 'unknown',
          window_size: 0,
          window_succeeded: 0,
          window_failed: 0,
          window_success_rate: null,
          timeout_count: 0,
          unavailable_count: 0,
          protocol_violation_count: 0,
          recent_failures: [],
          total_chains: 0,
          all_time_succeeded: 0,
          all_time_failed: 0,
          all_time_guard_rejected: 0,
          all_time_in_flight: 0,
          last_execution_at: null,
          last_execution_state: null,
        },
      },
    })
    routeFetch(() => json(200, populated))
    const body = await getExecutionHealth()
    expect(body).toEqual(populated)
    expect(body.adapters.mock.observed_status).toBe('healthy')
    expect(body.adapters.shuffle.observed_status).toBe('unknown')
    expect(body.adapters.shuffle.window_success_rate).toBeNull()
  })

  // ---------------------------------------------------------------- D
  it('surfaces backend errors as ApiError', async () => {
    routeFetch(() => json(500, { detail: 'Internal failure' }))
    await expect(getExecutionMetrics()).rejects.toBeInstanceOf(ApiError)
    await expect(getExecutionHealth()).rejects.toBeInstanceOf(ApiError)
  })

  // ---------------------------------------------------------------- E
  it('client source is GET-only: no write verbs, no Authorization', () => {
    const source = clientSource
    for (const banned of [
      'api.post',
      'api.patch',
      'api.put',
      'api.delete',
      'Authorization',
      'Bearer',
      'method:',
      'health_check',
      'shuffle',
      'wazuh',
      'thehive',
    ]) {
      expect(source, `banned token ${banned}`).not.toContain(banned)
    }
  })
})
