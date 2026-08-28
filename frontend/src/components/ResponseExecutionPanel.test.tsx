/** Phase 3.1.8: ResponseExecutionPanel unit tests (jsdom, fetch mocked).
 *
 * Locks the frozen Execute Console contract — the first UI able to trigger
 * a real execution:
 *   A. approved + no execution yet      -> Execute button
 *   B. pending (approval=null)          -> nothing, zero fetches
 *   C. rejected                         -> nothing, zero fetches
 *   D. modal opens with Operator / Execution Token / Comment
 *   E/F/G. POST body strictly mirrors the API (no smuggled facts) +
 *          Bearer header + fresh randomUUID execution identity
 *   H/I/J. 201 succeeded / failed / guard_rejected render as execution
 *          FACTS — guard_rejected is NOT an error banner
 *   K. 401 -> static message, token never reaches the DOM
 *   L. 409 -> backend stable message verbatim
 *   M. double-click submits exactly ONE request
 *   N. no action/target anywhere in the request
 *   O. token never persists (localStorage/sessionStorage empty, gone on
 *      unmount)
 *   P. page load fires zero POSTs (GET-only status lookup)
 *   Q. an existing forward execution renders its status instead of a
 *      duplicate Execute button
 */
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ResponseExecutionPanel } from './ResponseExecutionPanel'
import type { AIResponseApproval } from '../types/responseApproval'

const APPROVAL_ID = 'apr-1'
const TOKEN = 'exec-secret-never-leaks'
const TEST_UUID = '11111111-2222-4333-8444-555555555555'
const EXECUTIONS_URL = '/api/v1/executions'
/** Status lookup narrows to this approval (3.1.9 query contract). */
const STATUS_URL = `${EXECUTIONS_URL}?approval_id=${APPROVAL_ID}`

/** 3.1.9 paged envelope wrapper for status-lookup responses. */
function envelope(items: unknown[]) {
  return { total: items.length, page: 1, size: 20, items }
}

function approval(status: 'approved' | 'rejected'): AIResponseApproval {
  return {
    id: APPROVAL_ID,
    recommendation_id: 'rec-1',
    status,
    reviewer: 'alice',
    reviewed_at: '2026-08-27T11:00:00',
    review_comment: null,
    created_at: '2026-08-27T11:00:00',
    updated_at: '2026-08-27T11:00:00',
  }
}

function executionRead(derivedState: string, overrides: Record<string, unknown> = {}) {
  const terminalDetail =
    derivedState === 'failed'
      ? { classification: 'timeout', raw_response: {} }
      : derivedState === 'guard_rejected'
        ? { code: 'approval_not_approved', reason: "Approval status is 'rejected'" }
        : {}
  const decisions =
    derivedState === 'guard_rejected'
      ? ['requested', 'guard_rejected']
      : ['requested', 'dispatched', derivedState]
  return {
    execution_id: TEST_UUID,
    approval_id: APPROVAL_ID,
    direction: 'execute',
    action: 'block_source_ip',
    target: '203.0.113.10',
    derived_state: derivedState,
    chain: decisions,
    history: decisions.map((decision, i) => ({
      id: `row-${i}`,
      execution_id: TEST_UUID,
      approval_id: APPROVAL_ID,
      decision,
      direction: 'execute',
      action: 'block_source_ip',
      target: '203.0.113.10',
      operator: 'ops-01',
      detail: i === decisions.length - 1 ? terminalDetail : {},
      compensates_execution_id: null,
      created_at: `2026-08-27T12:00:0${i}`,
    })),
    ...overrides,
  }
}

function summary(overrides: Record<string, unknown> = {}) {
  return {
    execution_id: TEST_UUID,
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

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

type FetchHandler = (url: string, method: string) => Response | Promise<Response>

/** Route fetch by URL + method; unknown routes fail loudly in tests. */
function routeFetch(handler: FetchHandler) {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) =>
    handler(String(input), (init?.method ?? 'GET').toUpperCase()),
  )
  vi.stubGlobal('fetch', fn)
  return fn
}

/** GET /executions?approval_id=… -> paged envelope (default empty);
 * everything else 404. */
function statusFetch(list: unknown[] = []): FetchHandler {
  return (url, method) => {
    if (method === 'GET' && url === STATUS_URL) return json(200, envelope(list))
    return json(404, { detail: 'Not found' })
  }
}

/** Stub fetch (default: empty status lookup), render an approved panel and
 * open the modal. Returns the fetch mock for request assertions. */
async function openModal(handler: FetchHandler = statusFetch()) {
  const fetchMock = routeFetch(handler)
  render(<ResponseExecutionPanel approval={approval('approved')} />)
  const button = await screen.findByRole('button', { name: 'Execute' })
  fireEvent.click(button)
  await screen.findByRole('button', { name: 'Confirm Execute' })
  return fetchMock
}

/** POST /executions -> the given terminal fact; GET lookups stay empty. */
function postHandler(status: number, body: unknown): FetchHandler {
  return (url, method) => {
    if (method === 'GET' && url === STATUS_URL) return json(200, envelope([]))
    if (method === 'POST' && url === EXECUTIONS_URL) return json(status, body)
    return json(404, { detail: 'Not found' })
  }
}

async function fillModal(operator = 'ops-01', token = TOKEN, comment = '') {
  fireEvent.change(screen.getByLabelText('Operator'), { target: { value: operator } })
  fireEvent.change(screen.getByLabelText('Execution Token'), { target: { value: token } })
  if (comment) {
    fireEvent.change(screen.getByLabelText('Comment (optional)'), {
      target: { value: comment },
    })
  }
}

function postCalls(fetchMock: ReturnType<typeof routeFetch>) {
  return fetchMock.mock.calls.filter(([, init]) => (init?.method ?? 'GET') === 'POST')
}

describe('ResponseExecutionPanel', () => {
  beforeEach(() => {
    vi.unstubAllGlobals()
    // Deterministic execution identity: crypto.randomUUID(), stubbed so the
    // request assertions are exact (jsdom provides no randomUUID itself).
    vi.stubGlobal('crypto', { ...globalThis.crypto, randomUUID: () => TEST_UUID })
  })
  afterEach(() => {
    cleanup() // vitest globals are off, so RTL's auto-cleanup never registered
    vi.unstubAllGlobals()
  })

  it('A. approved + no execution yet shows the Execute button (GET-only lookup)', async () => {
    const fetchMock = routeFetch(statusFetch([]))
    render(<ResponseExecutionPanel approval={approval('approved')} />)

    expect(await screen.findByRole('button', { name: 'Execute' })).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(STATUS_URL)
    expect((init?.method ?? 'GET')).toBe('GET')
  })

  it('B. pending (approval=null) renders nothing and fires zero requests', () => {
    const fetchMock = routeFetch(statusFetch())
    const { container } = render(<ResponseExecutionPanel approval={null} />)

    expect(container).toBeEmptyDOMElement()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('C. rejected renders nothing and fires zero requests', () => {
    const fetchMock = routeFetch(statusFetch())
    const { container } = render(<ResponseExecutionPanel approval={approval('rejected')} />)

    expect(container).toBeEmptyDOMElement()
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('D. the modal collects Operator / Execution Token / Comment', async () => {
    await openModal()

    expect(screen.getByText('Execute Response')).toBeInTheDocument()
    expect(screen.getByLabelText('Operator')).toBeInTheDocument()
    expect(screen.getByLabelText('Execution Token')).toBeInTheDocument()
    expect(screen.getByLabelText('Comment (optional)')).toBeInTheDocument()
    expect(screen.getByLabelText('Execution Token')).toHaveAttribute('type', 'password')
    expect(screen.getByRole('button', { name: 'Confirm Execute' })).toBeDisabled()
  })

  it('E/F/G. Confirm POSTs the strict Intent body with Bearer header and a fresh execution_id', async () => {
    const fetchMock = await openModal(postHandler(201, executionRead('succeeded')))
    await fillModal('ops-01', TOKEN, 'contain the brute force')

    fireEvent.click(screen.getByRole('button', { name: 'Confirm Execute' }))
    await screen.findByText('Succeeded')

    const posts = postCalls(fetchMock)
    expect(posts).toHaveLength(1)
    const [url, init] = posts[0]
    expect(url).toBe(EXECUTIONS_URL)
    const headers = init?.headers as Record<string, string>
    expect(headers.Authorization).toBe(`Bearer ${TOKEN}`)
    expect(headers['Content-Type']).toBe('application/json')

    // N. the body is EXACTLY the frozen Intent — no smuggled facts
    const body = JSON.parse(init?.body as string)
    expect(Object.keys(body).sort()).toEqual(
      ['approval_id', 'comment', 'execution_id', 'operator'].sort(),
    )
    expect(body.execution_id).toBe(TEST_UUID) // randomUUID, not approval-derived
    expect(body.approval_id).toBe(APPROVAL_ID)
    expect(body.operator).toBe('ops-01')
    expect(body.comment).toBe('contain the brute force')
    for (const forbidden of ['action', 'target', 'direction', 'status', 'detail', 'created_at']) {
      expect(body).not.toHaveProperty(forbidden)
    }
  })

  it('H. 201 succeeded renders the execution fact directly — no follow-up GET', async () => {
    const fetchMock = await openModal(postHandler(201, executionRead('succeeded')))
    await fillModal()
    fireEvent.click(screen.getByRole('button', { name: 'Confirm Execute' }))

    expect(await screen.findByText('Succeeded')).toBeInTheDocument()
    expect(screen.getByText('requested → dispatched → succeeded')).toBeInTheDocument()
    expect(screen.getByText(TEST_UUID)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Confirm Execute' })).not.toBeInTheDocument()
    // fetch traffic = status GET + the single POST; nothing after the 201
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(postCalls(fetchMock)).toHaveLength(1)
  })

  it('I. 201 failed renders FAILED + the adapter classification', async () => {
    await openModal(postHandler(201, executionRead('failed')))
    await fillModal()
    fireEvent.click(screen.getByRole('button', { name: 'Confirm Execute' }))

    expect(await screen.findByText('Failed')).toBeInTheDocument()
    expect(screen.getByText('Classification')).toBeInTheDocument()
    expect(screen.getByText('timeout')).toBeInTheDocument()
  })

  it('J. 201 guard_rejected is an execution FACT, not an error banner', async () => {
    await openModal(postHandler(201, executionRead('guard_rejected')))
    await fillModal()
    fireEvent.click(screen.getByRole('button', { name: 'Confirm Execute' }))

    expect(await screen.findByText('Guard Rejected')).toBeInTheDocument()
    expect(screen.getByText('Reason')).toBeInTheDocument()
    expect(screen.getByText("Approval status is 'rejected'")).toBeInTheDocument()
    // the verdict renders as status — never as an error banner
    expect(document.querySelector('.error-banner')).toBeNull()
  })

  it('K. 401 shows a static credentials message and the token never reaches the DOM', async () => {
    await openModal(postHandler(401, { detail: 'Invalid execution credentials' }))
    await fillModal('ops-01', TOKEN)
    fireEvent.click(screen.getByRole('button', { name: 'Confirm Execute' }))

    expect(await screen.findByText('Execution credentials invalid')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain(TOKEN)
    // the modal stays open for a retry with corrected credentials
    expect(screen.getByRole('button', { name: 'Confirm Execute' })).toBeInTheDocument()
  })

  it('L. 409 surfaces the backend stable message verbatim', async () => {
    const serverMessage =
      'Concurrent execution conflict detected; the first execution’s facts stand'
    await openModal(
      postHandler(409, {
        detail: { error: 'ApprovalAlreadyExecuted', message: serverMessage },
      }),
    )
    await fillModal()
    fireEvent.click(screen.getByRole('button', { name: 'Confirm Execute' }))

    expect(await screen.findByText(serverMessage)).toBeInTheDocument()
  })

  it('M. same-tick double click submits exactly ONE request', async () => {
    let release: (value: Response) => void = () => {}
    const pending = new Promise<Response>((resolve) => {
      release = resolve
    })
    const fetchMock = await openModal((url, method) => {
      if (method === 'GET' && url === STATUS_URL) return json(200, envelope([]))
      if (method === 'POST' && url === EXECUTIONS_URL) return pending
      return json(404, { detail: 'Not found' })
    })
    await fillModal()

    const confirm = screen.getByRole('button', { name: 'Confirm Execute' })
    fireEvent.click(confirm)
    fireEvent.click(confirm) // second click in the SAME tick
    release(json(201, executionRead('succeeded')))

    expect(await screen.findByText('Succeeded')).toBeInTheDocument()
    expect(postCalls(fetchMock)).toHaveLength(1)
  })

  it('M2. while the request is in flight the button reads Submitting… and is disabled', async () => {
    const pending = new Promise<Response>(() => {}) // never resolves
    await openModal((url, method) => {
      if (method === 'GET' && url === STATUS_URL) return json(200, envelope([]))
      if (method === 'POST' && url === EXECUTIONS_URL) return pending
      return json(404, { detail: 'Not found' })
    })
    await fillModal()

    fireEvent.click(screen.getByRole('button', { name: 'Confirm Execute' }))

    const submitting = await screen.findByRole('button', { name: 'Submitting…' })
    expect(submitting).toBeDisabled()
  })

  it('O. the token is never persisted and dies with the modal', async () => {
    await openModal()
    await fillModal('ops-01', TOKEN)

    // cancel unmounts the modal — memory-only state dies with it
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))

    expect(screen.queryByRole('button', { name: 'Confirm Execute' })).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain(TOKEN)
    expect(localStorage.length).toBe(0)
    expect(sessionStorage.length).toBe(0)
  })

  it('O2. storage stays empty after a successful execution too', async () => {
    await openModal(postHandler(201, executionRead('succeeded')))
    await fillModal('ops-01', TOKEN)
    fireEvent.click(screen.getByRole('button', { name: 'Confirm Execute' }))
    await screen.findByText('Succeeded')

    expect(localStorage.length).toBe(0)
    expect(sessionStorage.length).toBe(0)
    expect(document.body.textContent).not.toContain(TOKEN)
  })

  it('P. mount never POSTs — the status lookup is GET-only', async () => {
    const fetchMock = routeFetch(statusFetch())
    render(<ResponseExecutionPanel approval={approval('approved')} />)
    await screen.findByRole('button', { name: 'Execute' })

    expect(postCalls(fetchMock)).toHaveLength(0)
    for (const [, init] of fetchMock.mock.calls) {
      expect(init?.method ?? 'GET').toBe('GET')
    }
  })

  it('Q. an existing forward execution renders its status — no duplicate Execute', async () => {
    const fetchMock = routeFetch((url, method) => {
      if (method === 'GET' && url === STATUS_URL)
        return json(200, envelope([summary({ derived_state: 'failed' })]))
      if (method === 'GET' && url === `${EXECUTIONS_URL}/${TEST_UUID}`)
        return json(200, executionRead('failed'))
      return json(404, { detail: 'Not found' })
    })
    render(<ResponseExecutionPanel approval={approval('approved')} />)

    expect(await screen.findByText('Failed')).toBeInTheDocument()
    expect(screen.getByText('timeout')).toBeInTheDocument()
    expect(screen.getByText(TEST_UUID)).toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Execute' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
    expect(screen.queryByRole('button', { name: 'Compensate' })).not.toBeInTheDocument()
    // exactly two GETs (list + detail), zero POSTs
    expect(postCalls(fetchMock)).toHaveLength(0)
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('R. a compensation chain never masquerades as the forward execution', async () => {
    // only a compensate-direction entry exists for this approval -> the
    // forward slot is still open, Execute stays available
    routeFetch((url, method) => {
      if (method === 'GET' && url === STATUS_URL)
        return json(200, envelope([summary({ direction: 'compensate' })]))
      return json(404, { detail: 'Not found' })
    })
    render(<ResponseExecutionPanel approval={approval('approved')} />)

    expect(await screen.findByRole('button', { name: 'Execute' })).toBeInTheDocument()
  })
})
