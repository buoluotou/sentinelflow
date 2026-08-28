/** ExecutionAuditPage unit tests (Phase 3.1.9, jsdom, fetch mocked).
 *
 * Locks the read-only audit contract:
 *   A. list renders the paged envelope as-is (server ordering, no re-derivation)
 *   B. empty list is a legal state, not an error
 *   C. filters are pure Filter -> GET query parameters
 *   D. pagination drives page= (server decides the window)
 *   E. state badges map derived_state facts
 *   F. backend errors surface as a banner
 *   G. zero action affordances (no Execute/Approve/Reject/Retry/Compensate)
 *   H. zero mutations + zero Authorization header on every request
 */
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ExecutionAuditPage } from './ExecutionAuditPage'

const LIST_URL = '/api/v1/executions'
const APPROVAL_ID = 'aaaa1111-2222-4333-8444-555555555555'

function summary(overrides: Record<string, unknown> = {}) {
  return {
    execution_id: '11111111-2222-4333-8444-555555555555',
    approval_id: APPROVAL_ID,
    direction: 'execute',
    action: 'block_source_ip',
    target: '203.0.113.10',
    operator: 'ops-01',
    derived_state: 'succeeded',
    chain: ['requested', 'dispatched', 'succeeded'],
    created_at: '2026-08-27T12:00:00',
    last_decision_at: '2026-08-27T12:00:02',
    ...overrides,
  }
}

function envelope(items: unknown[], overrides: Record<string, unknown> = {}) {
  return { total: items.length, page: 1, size: 20, items, ...overrides }
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

/** Default stub: every GET /executions* answers the given envelope. */
function listFetch(body: unknown) {
  return routeFetch((url, method) => {
    if (method === 'GET' && url.startsWith(LIST_URL)) return json(200, body)
    return json(404, { detail: 'Not found' })
  })
}

function lastUrl(fn: { mock: { calls: unknown[][] } }) {
  return fn.mock.calls[fn.mock.calls.length - 1][0] as string
}

function renderPage() {
  return render(
    <MemoryRouter initialEntries={['/executions']}>
      <ExecutionAuditPage />
    </MemoryRouter>,
  )
}

describe('ExecutionAuditPage', () => {
  beforeEach(() => {
    vi.unstubAllGlobals()
  })
  afterEach(() => {
    cleanup() // vitest globals are off, so RTL's auto-cleanup never registers
    vi.unstubAllGlobals()
  })

  it('A. renders the envelope rows — id/state/action/target/operator/approval/direction/last activity', async () => {
    listFetch(
      envelope([
        summary(),
        summary({
          execution_id: '99999999-8888-4777-8666-555555555555',
          action: 'isolate_host',
          target: 'host-01',
          operator: 'ops-02',
          derived_state: 'failed',
          direction: 'execute',
        }),
      ]),
    )
    renderPage()

    expect(await screen.findByText('11111111-2222-4333-8444-555555555555')).toBeInTheDocument()
    expect(screen.getByText('99999999-8888-4777-8666-555555555555')).toBeInTheDocument()
    expect(screen.getByText('block_source_ip')).toBeInTheDocument()
    expect(screen.getByText('isolate_host')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.10')).toBeInTheDocument()
    expect(screen.getByText('host-01')).toBeInTheDocument()
    expect(screen.getByText('ops-01')).toBeInTheDocument()
    expect(screen.getByText('Succeeded')).toBeInTheDocument()
    expect(screen.getByText('Failed')).toBeInTheDocument()
    expect(screen.getByText('2 executions')).toBeInTheDocument()
  })

  it('B. an empty list is a legal empty state, not an error', async () => {
    listFetch(envelope([]))
    renderPage()

    expect(
      await screen.findByText('No executions match the current filter.'),
    ).toBeInTheDocument()
    expect(document.querySelector('.error-banner')).toBeNull()
  })

  it('C. filters are pure Filter -> GET query parameters', async () => {
    const fetchMock = listFetch(envelope([]))
    renderPage()
    await screen.findByText('No executions match the current filter.')

    // initial load: page + size only
    expect(fetchMock.mock.calls[0][0]).toBe(`${LIST_URL}?page=1&size=20`)

    fireEvent.change(screen.getByLabelText('State'), { target: { value: 'failed' } })
    await screen.findByText('No executions match the current filter.')
    expect(lastUrl(fetchMock)).toBe(`${LIST_URL}?page=1&size=20&status=failed`)

    fireEvent.change(screen.getByLabelText('Direction'), { target: { value: 'compensate' } })
    await screen.findByText('No executions match the current filter.')
    expect(lastUrl(fetchMock)).toBe(
      `${LIST_URL}?page=1&size=20&status=failed&direction=compensate`,
    )

    fireEvent.change(screen.getByLabelText('Approval ID'), { target: { value: APPROVAL_ID } })
    await screen.findByText('No executions match the current filter.')
    expect(lastUrl(fetchMock)).toBe(
      `${LIST_URL}?page=1&size=20&status=failed&direction=compensate&approval_id=${APPROVAL_ID}`,
    )
  })

  it('C2. a malformed approval id never reaches the query (no 422-per-keystroke)', async () => {
    const fetchMock = listFetch(envelope([]))
    renderPage()
    await screen.findByText('No executions match the current filter.')

    fireEvent.change(screen.getByLabelText('Approval ID'), { target: { value: 'not-a-uuid' } })
    await screen.findByText('No executions match the current filter.')
    const last = lastUrl(fetchMock)
    expect(last).toBe(`${LIST_URL}?page=1&size=20`)
    expect(last).not.toContain('approval_id')
  })

  it('D. pagination sends page= and reflects the server total', async () => {
    // the envelope echoes the requested page — the pager trusts the server
    const fetchMock = routeFetch((url, method) => {
      if (method === 'GET' && url.startsWith(LIST_URL)) {
        const requested = Number(new URL(`http://x${url}`).searchParams.get('page'))
        return json(
          200,
          envelope([summary({ execution_id: 'exec-a' }), summary({ execution_id: 'exec-b' })], {
            total: 45,
            page: requested,
          }),
        )
      }
      return json(404, { detail: 'Not found' })
    })
    renderPage()

    expect(await screen.findByText('Page 1 / 3')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('button', { name: 'Next →' }))
    await screen.findByText('Page 2 / 3')
    expect(lastUrl(fetchMock)).toBe(`${LIST_URL}?page=2&size=20`)

    fireEvent.click(screen.getByRole('button', { name: '← Prev' }))
    await screen.findByText('Page 1 / 3')
    expect(lastUrl(fetchMock)).toBe(`${LIST_URL}?page=1&size=20`)
  })

  it('E. state badges render derived_state facts with the frozen semantics', async () => {
    listFetch(
      envelope([
        summary({ execution_id: 'e-1', derived_state: 'succeeded' }),
        summary({ execution_id: 'e-2', derived_state: 'failed' }),
        summary({ execution_id: 'e-3', derived_state: 'guard_rejected' }),
        summary({ execution_id: 'e-4', derived_state: 'compensation_requested' }),
      ]),
    )
    renderPage()

    expect(await screen.findByText('Succeeded')).toHaveClass('low')
    expect(screen.getByText('Failed')).toHaveClass('high')
    expect(screen.getByText('Guard Rejected')).toHaveClass('none')
    // the badge (not the filter <option>) carries the neutral chip class
    const neutral = screen
      .getAllByText('compensation requested')
      .find((el) => el.classList.contains('badge'))
    expect(neutral).toHaveClass('none')
  })

  it('F. a backend failure surfaces as an error banner', async () => {
    routeFetch(() => json(500, { detail: 'Internal server error' }))
    renderPage()

    expect(await screen.findByText('Internal server error')).toBeInTheDocument()
    expect(document.querySelector('.error-banner')).not.toBeNull()
  })

  it('G. zero action affordances — the only buttons are the pager', async () => {
    listFetch(envelope([summary()]))
    renderPage()
    await screen.findByText('11111111-2222-4333-8444-555555555555')

    const buttons = screen.queryAllByRole('button')
    const names = buttons.map((b) => b.textContent ?? '')
    expect(names.sort()).toEqual(['Next →', '← Prev'])
    for (const forbidden of [/execute/i, /approve/i, /reject/i, /retry/i, /compensate/i, /run response/i]) {
      expect(names.join(' ')).not.toMatch(forbidden)
    }
  })

  it('H. GET-only traffic, zero mutations, zero Authorization headers', async () => {
    const fetchMock = listFetch(envelope([summary()]))
    renderPage()
    await screen.findByText('11111111-2222-4333-8444-555555555555')

    for (const [url, init] of fetchMock.mock.calls) {
      expect((init?.method ?? 'GET').toUpperCase()).toBe('GET')
      expect(String(url).startsWith(LIST_URL)).toBe(true)
      const headers = (init?.headers ?? {}) as Record<string, string>
      expect(headers.Authorization).toBeUndefined()
      expect(headers.authorization).toBeUndefined()
    }
  })
})
