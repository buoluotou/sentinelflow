/** ExecutionDetailPage unit tests (Phase 3.1.9, jsdom, fetch mocked).
 *
 * Locks the read-only detail contract:
 *   A. the append-only timeline renders every decision row in order
 *   B. detail blocks are collapsed by default; the expander toggles them
 *   C. detail payloads render as escaped text — never as live HTML
 *   D. compensation relation: "Compensates" (compensate direction)
 *   E. compensation relation: "Compensated by" (execute direction)
 *   F. a 404 surfaces as an error banner
 *   G. zero action affordances — only the detail expander exists
 *   H. GET-only traffic, zero mutations, zero Authorization headers
 */
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ExecutionDetailPage } from './ExecutionDetailPage'

const EXEC_ID = '11111111-2222-4333-8444-555555555555'
const COMP_ID = '99999999-8888-4777-8666-555555555555'
const APPROVAL_ID = 'aaaa1111-2222-4333-8444-555555555555'
const DETAIL_URL = `/api/v1/executions/${EXEC_ID}`
/** Compensation discovery lookup for a forward (execute) chain. */
const COMP_LOOKUP_URL = `/api/v1/executions?direction=compensate&approval_id=${APPROVAL_ID}`

function row(id: string, decision: string, detail: Record<string, unknown> = {}) {
  return {
    id,
    execution_id: EXEC_ID,
    approval_id: APPROVAL_ID,
    decision,
    direction: 'execute',
    action: 'block_source_ip',
    target: '203.0.113.10',
    operator: 'ops-01',
    detail,
    compensates_execution_id: null,
    created_at: `2026-08-27T12:00:0${id.slice(-1)}`,
  }
}

function executionRead(overrides: Record<string, unknown> = {}) {
  return {
    execution_id: EXEC_ID,
    approval_id: APPROVAL_ID,
    direction: 'execute',
    action: 'block_source_ip',
    target: '203.0.113.10',
    derived_state: 'failed',
    chain: ['requested', 'dispatched', 'failed'],
    history: [
      row('row-0', 'requested'),
      row('row-1', 'dispatched'),
      row('row-2', 'failed', {
        classification: 'timeout',
        raw_response: { error: '<img src=x onerror=alert(1)>' },
      }),
    ],
    ...overrides,
  }
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

type FetchHandler = (url: string, method: string) => Response | Promise<Response>

function routeFetch(handler: FetchHandler) {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) =>
    handler(String(input), (init?.method ?? 'GET').toUpperCase()),
  )
  vi.stubGlobal('fetch', fn)
  return fn
}

/** Detail + optional compensation lookup; everything else 404. */
function detailFetch(
  detail: unknown,
  compensation: unknown[] = [],
): FetchHandler {
  return (url, method) => {
    if (method === 'GET' && url === DETAIL_URL) return json(200, detail)
    if (method === 'GET' && url === COMP_LOOKUP_URL)
      return json(200, { total: compensation.length, page: 1, size: 20, items: compensation })
    return json(404, { detail: 'Not found' })
  }
}

function renderDetail() {
  return render(
    <MemoryRouter initialEntries={[`/executions/${EXEC_ID}`]}>
      <Routes>
        <Route path="/executions/:id" element={<ExecutionDetailPage />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('ExecutionDetailPage', () => {
  beforeEach(() => {
    vi.unstubAllGlobals()
  })
  afterEach(() => {
    cleanup() // vitest globals are off, so RTL's auto-cleanup never registers
    vi.unstubAllGlobals()
  })

  it('A. renders the full append-only timeline in decision order', async () => {
    routeFetch(detailFetch(executionRead()))
    renderDetail()

    expect(await screen.findByText('requested')).toBeInTheDocument()
    expect(screen.getByText('dispatched')).toBeInTheDocument()
    expect(screen.getByText('failed')).toBeInTheDocument()
    expect(screen.getByText('Failed')).toBeInTheDocument() // state badge
    expect(screen.getByText('block_source_ip')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.10')).toBeInTheDocument()
    expect(screen.getByText(APPROVAL_ID)).toBeInTheDocument()
  })

  it('B. detail is collapsed by default; the expander toggles it', async () => {
    routeFetch(detailFetch(executionRead()))
    renderDetail()
    await screen.findByText('requested')

    // collapsed: the adapter payload is NOT in the DOM yet
    expect(screen.queryByText(/classification/)).not.toBeInTheDocument()
    expect(screen.queryByText(/onerror/)).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Show detail' }))
    expect(await screen.findByText(/timeout/)).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Hide detail' }))
    expect(screen.queryByText(/timeout/)).not.toBeInTheDocument()
  })

  it('C. detail renders as escaped text — never live HTML', async () => {
    routeFetch(detailFetch(executionRead()))
    renderDetail()
    await screen.findByText('requested')

    fireEvent.click(screen.getByRole('button', { name: 'Show detail' }))
    await screen.findByText(/timeout/)

    // the payload is visible as text, but never became a live element
    expect(document.body.textContent).toContain('<img src=x onerror=alert(1)>')
    expect(document.querySelector('img')).toBeNull()
    expect(document.body.innerHTML).toContain('&lt;img src=x onerror=alert(1)&gt;')
  })

  it('D. a compensation chain shows "Compensates: <forward execution>"', async () => {
    routeFetch((url, method) => {
      if (method === 'GET' && url === `/api/v1/executions/${COMP_ID}`)
        return json(
          200,
          executionRead({
          execution_id: COMP_ID,
          direction: 'compensate',
          chain: ['compensation_requested', 'dispatched', 'compensation_succeeded'],
          derived_state: 'compensation_succeeded',
          history: [
            {
              ...row('row-0', 'compensation_requested'),
              execution_id: COMP_ID,
              direction: 'compensate',
              compensates_execution_id: EXEC_ID,
            },
          ],
          }),
        )
      return json(404, { detail: 'Not found' })
    })
    render(
      <MemoryRouter initialEntries={[`/executions/${COMP_ID}`]}>
        <Routes>
          <Route path="/executions/:id" element={<ExecutionDetailPage />} />
        </Routes>
      </MemoryRouter>,
    )

    expect(await screen.findByText(/Compensates:/)).toBeInTheDocument()
    const link = screen.getByRole('link', { name: EXEC_ID })
    expect(link).toHaveAttribute('href', `/executions/${EXEC_ID}`)
    // a compensate-direction entry never claims a "Compensated by" slot
    expect(screen.queryByText('Compensated by:')).not.toBeInTheDocument()
  })

  it('E. a forward execution shows "Compensated by" from the filtered lookup', async () => {
    const fetchMock = routeFetch(
      detailFetch(executionRead(), [
        { execution_id: COMP_ID, approval_id: APPROVAL_ID, direction: 'compensate' },
      ]),
    )
    renderDetail()

    expect(await screen.findByText(/Compensated by:/)).toBeInTheDocument()
    const link = await screen.findByRole('link', { name: COMP_ID })
    expect(link).toHaveAttribute('href', `/executions/${COMP_ID}`)
    // the discovery used the frozen read contract — no new endpoint
    expect(fetchMock.mock.calls.some(([url]) => url === COMP_LOOKUP_URL)).toBe(true)
  })

  it('E2. a forward execution without compensation reads "none"', async () => {
    routeFetch(detailFetch(executionRead(), []))
    renderDetail()

    expect(await screen.findByText(/Compensated by:/)).toBeInTheDocument()
    expect(screen.getByText('none')).toBeInTheDocument()
  })

  it('F. a 404 detail surfaces as an error banner', async () => {
    routeFetch(() => json(404, { detail: 'Execution not found' }))
    renderDetail()

    expect(await screen.findByText('Execution not found')).toBeInTheDocument()
    expect(document.querySelector('.error-banner')).not.toBeNull()
  })

  it('G. zero action affordances — only the detail expander exists', async () => {
    routeFetch(detailFetch(executionRead()))
    renderDetail()
    await screen.findByText('requested')

    const names = screen.queryAllByRole('button').map((b) => b.textContent ?? '')
    expect(names).toEqual(['Show detail'])
    for (const forbidden of [/execute/i, /approve/i, /reject/i, /retry/i, /compensate/i, /run response/i]) {
      expect(names.join(' ')).not.toMatch(forbidden)
    }
  })

  it('H. GET-only traffic, zero mutations, zero Authorization headers', async () => {
    const fetchMock = routeFetch(detailFetch(executionRead()))
    renderDetail()
    await screen.findByText('requested')
    await screen.findByText(/Compensated by:/)

    expect(fetchMock.mock.calls.length).toBeGreaterThanOrEqual(2)
    for (const [url, init] of fetchMock.mock.calls) {
      expect((init?.method ?? 'GET').toUpperCase()).toBe('GET')
      expect(String(url).startsWith('/api/v1/executions')).toBe(true)
      const headers = (init?.headers ?? {}) as Record<string, string>
      expect(headers.Authorization).toBeUndefined()
      expect(headers.authorization).toBeUndefined()
    }
  })
})
