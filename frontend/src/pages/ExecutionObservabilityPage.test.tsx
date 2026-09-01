/** ExecutionObservabilityPage unit tests (Phase 3.3.3.4.2, jsdom, fetch
 * mocked).
 *
 * Locks the pure read-only observability contract:
 *   A. metrics render the six frozen cards from the server body
 *   B. adapter health renders the observed verdict + recent window facts
 *   C. null -> N/A (never 0%)
 *   D. all four observed statuses reachable, always labelled "Observed"
 *   E. multi-adapter rendering (deterministic sorted order)
 *   F. empty data -> N/A cards + "No adapter observations" (never "failing")
 *   G. any GET failure surfaces through the shared ErrorBanner
 *   H. page load issues GETs ONLY (exactly the two frozen endpoints)
 *   I. zero Authorization header on every request (no token)
 *   J. zero buttons / action affordances on the page
 *   K. zero write verbs anywhere in the page source
 *   L. both read models load together (two GETs on mount)
 *   M. server rates render verbatim — the UI never recomputes a rate
 *      from sibling numbers (0.8 -> 80% even when counts say otherwise)
 */
import { cleanup, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ExecutionObservabilityPage } from './ExecutionObservabilityPage'
// Vite ?raw import: the page's source text, for the structural lock K
// (no node fs in the browser tsconfig).
import pageSource from './ExecutionObservabilityPage.tsx?raw'

const METRICS_URL = '/api/v1/executions/metrics'
const HEALTH_URL = '/api/v1/executions/health'

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

function metricsBody(overrides: Record<string, unknown> = {}) {
  return {
    total_chains: 10,
    executed_chains: 8,
    succeeded: 3,
    failed: 5,
    guard_rejected: 2,
    in_flight: 0,
    success_rate: 0.375,
    executor_failure_rate: 0.625,
    guard_rejection_rate: 0.2,
    rejections_by_source: { policy: 1, guard: 1 },
    failure_classifications: { timeout: 3, adapter_error: 1, protocol_violation: 1 },
    latency: { count: 8, average_seconds: 1.25, min_seconds: 0.1, max_seconds: 4.2 },
    by_adapter: {},
    ...overrides,
  }
}

function adapterHealth(adapter: string, overrides: Record<string, unknown> = {}) {
  return {
    adapter,
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

type FetchHandler = (url: string, init?: RequestInit) => Response

/** Routes the two frozen GET endpoints; anything else 404s loudly. */
function routeFetch(
  handler: FetchHandler,
): ReturnType<typeof vi.fn> & { mock: { calls: unknown[][] } } {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) =>
    handler(String(input), init),
  )
  vi.stubGlobal('fetch', fn)
  return fn
}

function observabilityFetch(
  metrics: Response,
  health: Response,
): ReturnType<typeof vi.fn> & { mock: { calls: unknown[][] } } {
  return routeFetch((url) => {
    if (url === METRICS_URL) return metrics
    if (url === HEALTH_URL) return health
    return json(404, { detail: `unexpected request: ${url}` })
  })
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/observability']}>
      <ExecutionObservabilityPage />
    </MemoryRouter>,
  )
}

describe('ExecutionObservabilityPage', () => {
  beforeEach(() => {
    vi.unstubAllGlobals()
  })
  afterEach(() => {
    cleanup() // vitest globals are off, so RTL's auto-cleanup never registered
    vi.unstubAllGlobals()
  })

  // ------------------------------------------------------------------ A
  it('A. renders the six metrics cards from the server body', async () => {
    observabilityFetch(json(200, metricsBody()), json(200, healthBody()))
    renderPage()
    expect(await screen.findByText('Total Executions')).toBeDefined()
    expect(screen.getByText('Succeeded')).toBeDefined()
    expect(screen.getByText('Failed')).toBeDefined()
    expect(screen.getByText('Guard Rejected')).toBeDefined()
    expect(screen.getByText('Success Rate')).toBeDefined()
    expect(screen.getByText('Guard Rejection Rate')).toBeDefined()
    // values are the server's numbers, verbatim
    expect(screen.getByText('10')).toBeDefined()
    expect(screen.getByText('3')).toBeDefined()
    expect(screen.getByText('5')).toBeDefined()
    expect(screen.getByText('2')).toBeDefined()
    expect(screen.getByText('37.5%')).toBeDefined()
    expect(screen.getByText('20%')).toBeDefined()
  })

  // ------------------------------------------------------------------ B
  it('B. renders adapter health: observed verdict + recent window facts', async () => {
    observabilityFetch(
      json(200, metricsBody()),
      json(
        200,
        healthBody({
          adapters: {
            shuffle: adapterHealth('shuffle', {
              observed_status: 'degraded',
              window_success_rate: 0.75,
              window_failed: 3,
              timeout_count: 2,
              unavailable_count: 1,
            }),
          },
        }),
      ),
    )
    renderPage()
    const card = await screen.findByTestId('adapter-shuffle')
    expect(screen.getByText('Observed: degraded')).toBeDefined()
    expect(card.textContent).toContain('Recent Success Rate: 75%')
    expect(card.textContent).toContain('Recent Failed: 3')
    expect(card.textContent).toContain('Timeout: 2')
    expect(card.textContent).toContain('Unavailable: 1')
    expect(card.textContent).toContain('Last Execution:')
    expect(card.textContent).toContain('(succeeded)')
    // the caption makes the read-model semantics explicit
    expect(
      screen.getByText(/Observed health — derived from recent execution facts/),
    ).toBeDefined()
  })

  // ------------------------------------------------------------------ C
  it('C. null rates render as N/A, never as 0%', async () => {
    observabilityFetch(
      json(
        200,
        metricsBody({
          total_chains: 0,
          executed_chains: 0,
          succeeded: 0,
          failed: 0,
          guard_rejected: 0,
          success_rate: null,
          executor_failure_rate: null,
          guard_rejection_rate: null,
        }),
      ),
      json(200, healthBody()),
    )
    renderPage()
    await screen.findByText('Total Executions')
    expect(screen.getAllByText('N/A').length).toBe(2)
    expect(screen.queryByText('0%')).toBeNull()
  })

  // ------------------------------------------------------------------ D
  it('D. all four observed statuses reachable, always labelled Observed', async () => {
    observabilityFetch(
      json(200, metricsBody()),
      json(
        200,
        healthBody({
          adapters: {
            a: adapterHealth('a', { observed_status: 'healthy' }),
            b: adapterHealth('b', { observed_status: 'degraded' }),
            c: adapterHealth('c', { observed_status: 'failing' }),
            d: adapterHealth('d', { observed_status: 'unknown' }),
          },
        }),
      ),
    )
    renderPage()
    await screen.findByTestId('adapter-a')
    for (const word of ['healthy', 'degraded', 'failing', 'unknown']) {
      expect(screen.getByText(`Observed: ${word}`)).toBeDefined()
    }
    // a bare verdict word never appears without the "Observed" prefix
    expect(screen.queryByText(/^healthy$/)).toBeNull()
  })

  // ------------------------------------------------------------------ E
  it('E. renders multiple adapters in deterministic sorted order', async () => {
    observabilityFetch(
      json(200, metricsBody()),
      json(
        200,
        healthBody({
          adapters: {
            wazuh: adapterHealth('wazuh'),
            mock: adapterHealth('mock'),
            thehive: adapterHealth('thehive'),
            shuffle: adapterHealth('shuffle'),
          },
        }),
      ),
    )
    renderPage()
    await screen.findByTestId('adapter-mock')
    const cards = screen.getAllByTestId(/^adapter-/)
    expect(cards.map((c) => c.getAttribute('data-testid'))).toEqual([
      'adapter-mock',
      'adapter-shuffle',
      'adapter-thehive',
      'adapter-wazuh',
    ])
  })

  // ------------------------------------------------------------------ F
  it('F. empty data: N/A metrics + "No adapter observations", never failing', async () => {
    observabilityFetch(
      json(
        200,
        metricsBody({
          total_chains: 0,
          executed_chains: 0,
          succeeded: 0,
          failed: 0,
          guard_rejected: 0,
          success_rate: null,
          executor_failure_rate: null,
          guard_rejection_rate: null,
        }),
      ),
      json(200, healthBody()),
    )
    renderPage()
    expect(await screen.findByText('No adapter observations')).toBeDefined()
    expect(screen.queryByText(/Observed: failing/)).toBeNull()
    expect(screen.queryByTestId(/^adapter-/)).toBeNull()
  })

  // ------------------------------------------------------------------ G
  it('G. metrics failure surfaces through the shared ErrorBanner', async () => {
    observabilityFetch(json(500, { detail: 'metrics down' }), json(200, healthBody()))
    renderPage()
    expect(await screen.findByText(/metrics down|500/)).toBeDefined()
    expect(screen.queryByText('Total Executions')).toBeNull()
  })

  it('G2. health failure surfaces through the shared ErrorBanner', async () => {
    observabilityFetch(json(200, metricsBody()), json(503, { detail: 'health down' }))
    renderPage()
    expect(await screen.findByText(/health down|503/)).toBeDefined()
    expect(screen.queryByText('Execution Metrics')).toBeNull()
  })

  // ----------------------------------------------------------- H + I + L
  it('H/I/L. exactly two GETs on mount, correct URLs, no Authorization', async () => {
    const fn = observabilityFetch(json(200, metricsBody()), json(200, healthBody()))
    renderPage()
    await screen.findByText('Total Executions')
    const urls = fn.mock.calls.map((c) => String(c[0])).sort()
    expect(urls).toEqual([HEALTH_URL, METRICS_URL])
    for (const call of fn.mock.calls) {
      const init = call[1] as RequestInit | undefined
      expect((init?.method ?? 'GET').toUpperCase()).toBe('GET')
      const headers = (init?.headers ?? {}) as Record<string, string>
      expect(headers.Authorization).toBeUndefined()
    }
  })

  // ------------------------------------------------------------------ J
  it('J. the page has zero buttons / action affordances', async () => {
    observabilityFetch(
      json(200, metricsBody()),
      json(
        200,
        healthBody({ adapters: { mock: adapterHealth('mock') } }),
      ),
    )
    renderPage()
    await screen.findByText('Total Executions')
    expect(screen.queryAllByRole('button')).toHaveLength(0)
    // banned execution vocabulary never appears on the page
    for (const word of ['Execute', 'Retry', 'Compensate', 'Approve', 'Reject', 'Run Response']) {
      expect(screen.queryByText(new RegExp(`\\b${word}\\b`))).toBeNull()
    }
  })

  // ------------------------------------------------------------------ K
  it('K. page source carries no write verbs, no token vocabulary', () => {
    const source = pageSource
    for (const banned of [
      'api.post',
      'api.patch',
      'api.put',
      'api.delete',
      'method:',
      'Authorization',
      'Bearer',
      'token',
      'health_check',
      '<button',
    ]) {
      expect(source, `banned token ${banned}`).not.toContain(banned)
    }
  })

  // ------------------------------------------------------------------ M
  it('M. server rates render verbatim — the UI never recomputes them', async () => {
    // Deliberately inconsistent-looking companions: if the UI recomputed
    // success_rate from succeeded/(succeeded+failed) it would show 40%,
    // not the server's frozen 0.8.
    observabilityFetch(
      json(
        200,
        metricsBody({
          succeeded: 4,
          failed: 6,
          success_rate: 0.8,
          guard_rejection_rate: 0.125,
        }),
      ),
      json(
        200,
        healthBody({
          adapters: {
            mock: adapterHealth('mock', {
              window_succeeded: 1,
              window_failed: 3,
              window_success_rate: 0.9,
            }),
          },
        }),
      ),
    )
    renderPage()
    await screen.findByText('Total Executions')
    expect(screen.getByText('80%')).toBeDefined()
    expect(screen.getByText('12.5%')).toBeDefined()
    expect(screen.queryByText('40%')).toBeNull()
    const card = screen.getByTestId('adapter-mock')
    expect(card.textContent).toContain('Recent Success Rate: 90%')
    expect(card.textContent).not.toContain('25%')
  })
})
