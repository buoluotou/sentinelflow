/** Step 13.5: ApprovalQueuePage unit tests (jsdom, fetch mocked).
 *
 * Locks the frozen UI contract of the Step 13.3 backend projection:
 * GET /approvals is the ONLY queue source (rendered as-is, never re-sorted,
 * never recomputed), approve/reject POST { reviewer, review_comment } only
 * (never reviewed_at), 201 -> local removal, 409 -> server queue re-fetched
 * as the source of truth, 200+[] is a normal empty state while a failed GET
 * is NEVER disguised as an empty queue. Approve != Execute: the page has no
 * execution affordance and never touches /incidents.
 */
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ApprovalQueuePage } from './ApprovalQueuePage'

const SIX_ACTIONS = [
  'block_source_ip',
  'isolate_host',
  'disable_account',
  'hunt_related_activity',
  'escalate_to_incident',
  'monitor_only',
] as const

/** One PendingApprovalRead entry; carries a smuggled risk_score to prove the
 * UI never renders one (the queue projection has no such field). */
function pendingItem(overrides: Record<string, unknown> = {}) {
  return {
    id: 'rec-1',
    event_id: 'evt-1',
    event_title: 'SSH Brute Force',
    provider: 'ollama',
    model: 'qwen3:4b',
    overall_rationale: 'Coordinated response is recommended for this event.',
    recommendations: [
      {
        action: 'block_source_ip',
        target: '203.0.113.10',
        rationale: 'Repeated authentication abuse from this source.',
      },
    ],
    confidence: 0.92,
    created_at: '2026-08-26T02:59:01',
    risk_score: 88, // must NEVER be rendered
    ...overrides,
  }
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

type Call = { url: string; method: string; body?: unknown }

interface Route {
  queue?: () => Response | Promise<Response>
  approve?: () => Response | Promise<Response>
  reject?: () => Response | Promise<Response>
}

/** Scripted fetch: records every call and routes by URL + method. */
function mockFetch(routes: Route) {
  const calls: Call[] = []
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const method = (init?.method ?? 'GET').toUpperCase()
    calls.push({
      url,
      method,
      body: init?.body ? JSON.parse(String(init.body)) : undefined,
    })
    if (method === 'GET') return (routes.queue ?? (() => json(200, [])))()
    if (url.endsWith('/approve')) return routes.approve?.() ?? json(201, {})
    return routes.reject?.() ?? json(201, {})
  })
  vi.stubGlobal('fetch', fn)
  return { fn, calls }
}

const posts = (calls: Call[]) => calls.filter((c) => c.method === 'POST')
const gets = (calls: Call[]) => calls.filter((c) => c.method === 'GET')

describe('ApprovalQueuePage', () => {
  afterEach(() => {
    cleanup() // vitest globals are off, so RTL's auto-cleanup never registered
    vi.unstubAllGlobals()
  })

  it('GET /approvals renders the queue — event_title, actions, targets, rationale, confidence', async () => {
    const { calls } = mockFetch({ queue: () => json(200, [pendingItem()]) })
    render(<ApprovalQueuePage />)

    expect(await screen.findByText('SSH Brute Force')).toBeInTheDocument()
    expect(screen.getByText('Block Source IP')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.10')).toBeInTheDocument()
    expect(
      screen.getByText('Rationale: Repeated authentication abuse from this source.'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('Coordinated response is recommended for this event.'),
    ).toBeInTheDocument()
    expect(screen.getByText('92%')).toBeInTheDocument()

    expect(gets(calls)).toHaveLength(1)
    expect(gets(calls)[0].url).toBe('/api/v1/approvals')
  })

  it('renders every entry in backend order with a pending count (never re-sorted)', async () => {
    mockFetch({
      queue: () =>
        json(200, [
          pendingItem({ id: 'rec-a', event_title: 'Event A' }),
          pendingItem({ id: 'rec-b', event_title: 'Event B' }),
          pendingItem({ id: 'rec-c', event_title: 'Event C' }),
        ]),
    })
    render(<ApprovalQueuePage />)

    await screen.findByText('Event A')
    const titles = screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)
    expect(titles).toEqual(['Event A', 'Event B', 'Event C']) // backend order as-is
    expect(screen.getByText('3 pending')).toBeInTheDocument()
  })

  it('renders all six frozen actions with readable labels', async () => {
    const items = SIX_ACTIONS.map((action) => ({
      action,
      target: 'host-1',
      rationale: `rationale for ${action}`,
    }))
    mockFetch({
      queue: () => json(200, [pendingItem({ recommendations: items })]),
    })
    render(<ApprovalQueuePage />)

    expect(await screen.findByText('Block Source IP')).toBeInTheDocument()
    expect(screen.getByText('Isolate Host')).toBeInTheDocument()
    expect(screen.getByText('Disable Account')).toBeInTheDocument()
    expect(screen.getByText('Hunt Related Activity')).toBeInTheDocument()
    expect(screen.getByText('Escalate to Incident')).toBeInTheDocument()
    expect(screen.getByText('Monitor Only')).toBeInTheDocument()
  })

  it('shows a shared page-level reviewer input and an optional per-item comment', async () => {
    mockFetch({ queue: () => json(200, [pendingItem()]) })
    render(<ApprovalQueuePage />)

    const reviewer = await screen.findByLabelText('Reviewer')
    expect(reviewer).toHaveValue('analyst-01') // default identity, editable
    expect(screen.getByLabelText('Review comment')).toHaveValue('') // optional, empty
  })

  it('loading state first — empty-state text never shown before the queue arrives', () => {
    let resolveQueue!: (value: Response) => void
    mockFetch({
      queue: () =>
        new Promise<Response>((resolve) => {
          resolveQueue = resolve
        }),
    })
    render(<ApprovalQueuePage />)

    expect(screen.getByText('Loading approval queue…')).toBeInTheDocument()
    expect(screen.queryByText('No pending recommendations.')).not.toBeInTheDocument()
    resolveQueue(json(200, []))
  })

  it('200 + [] is the normal empty state — not an error', async () => {
    mockFetch({ queue: () => json(200, []) })
    render(<ApprovalQueuePage />)

    expect(await screen.findByText('No pending recommendations.')).toBeInTheDocument()
    expect(document.querySelector('.error-banner')).toBeNull()
    expect(screen.queryByText('Loading approval queue…')).not.toBeInTheDocument()
  })

  it('GET 503 surfaces the backend error and is NEVER disguised as an empty queue', async () => {
    mockFetch({ queue: () => json(503, { detail: 'Backend unavailable' }) })
    render(<ApprovalQueuePage />)

    expect(await screen.findByText('Backend unavailable')).toBeInTheDocument()
    expect(document.querySelector('.error-banner')).not.toBeNull()
    expect(screen.queryByText('No pending recommendations.')).not.toBeInTheDocument()
    expect(screen.queryByText('Loading approval queue…')).not.toBeInTheDocument()
  })

  it('Approve POSTs { reviewer, review_comment } to .../approve — never reviewed_at', async () => {
    const { calls } = mockFetch({ queue: () => json(200, [pendingItem()]) })
    render(<ApprovalQueuePage />)
    fireEvent.change(await screen.findByLabelText('Review comment'), {
      target: { value: 'Confirmed malicious activity.' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }))

    await screen.findByText('No pending recommendations.')
    const post = posts(calls)[0]
    expect(posts(calls)).toHaveLength(1)
    expect(post.url).toBe('/api/v1/response-recommendations/rec-1/approve')
    expect(post.body).toEqual({
      reviewer: 'analyst-01',
      review_comment: 'Confirmed malicious activity.',
    })
    expect(post.body).not.toHaveProperty('reviewed_at') // server stamps the clock
  })

  it('Reject POSTs to .../reject with an empty comment sent as null', async () => {
    const { calls } = mockFetch({ queue: () => json(200, [pendingItem()]) })
    render(<ApprovalQueuePage />)
    fireEvent.click(await screen.findByRole('button', { name: 'Reject' }))

    await screen.findByText('No pending recommendations.')
    const post = posts(calls)[0]
    expect(posts(calls)).toHaveLength(1)
    expect(post.url).toBe('/api/v1/response-recommendations/rec-1/reject')
    expect(post.body).toEqual({ reviewer: 'analyst-01', review_comment: null })
  })

  it('201 removes the item locally without a follow-up GET — count 2 -> 1', async () => {
    const { calls } = mockFetch({
      queue: () =>
        json(200, [
          pendingItem({ id: 'rec-a', event_title: 'Event A' }),
          pendingItem({ id: 'rec-b', event_title: 'Event B' }),
        ]),
    })
    render(<ApprovalQueuePage />)

    const [cardA] = await screen.findAllByRole('button', { name: 'Approve' })
    fireEvent.click(cardA) // first card = Event A (backend order)

    await screen.findByText('1 pending')
    expect(screen.queryByText('Event A')).not.toBeInTheDocument()
    expect(screen.getByText('Event B')).toBeInTheDocument()
    expect(gets(calls)).toHaveLength(1) // 201 -> local removal, no re-GET
  })

  it('shows Approving… and disables BOTH decision buttons while the POST is in flight', async () => {
    let resolvePost!: (value: Response) => void
    mockFetch({
      queue: () => json(200, [pendingItem()]),
      approve: () =>
        new Promise<Response>((resolve) => {
          resolvePost = resolve
        }),
    })
    render(<ApprovalQueuePage />)

    const approve = await screen.findByRole('button', { name: 'Approve' })
    const reject = screen.getByRole('button', { name: 'Reject' })
    fireEvent.click(approve)

    expect(await screen.findByText('Approving…')).toBeInTheDocument()
    expect(approve).toBeDisabled()
    expect(reject).toBeDisabled()
    resolvePost(json(201, {}))
    await screen.findByText('No pending recommendations.')
  })

  it('double-click never stacks a second POST (one decision per click)', async () => {
    let resolvePost!: (value: Response) => void
    const { calls } = mockFetch({
      queue: () => json(200, [pendingItem()]),
      approve: () =>
        new Promise<Response>((resolve) => {
          resolvePost = resolve
        }),
    })
    render(<ApprovalQueuePage />)

    const approve = await screen.findByRole('button', { name: 'Approve' })
    fireEvent.click(approve)
    fireEvent.click(approve) // double click while in flight
    resolvePost(json(201, {}))
    await screen.findByText('No pending recommendations.')

    expect(posts(calls)).toHaveLength(1)
  })

  it('409 refetches the server queue as the source of truth (another reviewer won)', async () => {
    const { calls } = mockFetch({
      queue: vi
        .fn()
        .mockReturnValueOnce(json(200, [pendingItem()]))
        .mockReturnValueOnce(json(200, [])), // the rival already decided
      approve: () => json(409, { detail: 'Recommendation already reviewed' }),
    } as Route)
    render(<ApprovalQueuePage />)

    fireEvent.click(await screen.findByRole('button', { name: 'Approve' }))

    await screen.findByText('No pending recommendations.') // from the REFRESH
    expect(gets(calls)).toHaveLength(2) // initial load + 409-driven refresh
    expect(screen.queryByText('SSH Brute Force')).not.toBeInTheDocument()
  })

  it('never renders a risk score, even when the payload smuggles one in', async () => {
    mockFetch({ queue: () => json(200, [pendingItem()]) })
    render(<ApprovalQueuePage />)
    await screen.findByText('92%')

    expect(screen.queryByText(/risk score/i)).not.toBeInTheDocument()
    expect(screen.queryByText('88')).not.toBeInTheDocument()
  })

  it('has no execution affordance — only Approve / Reject per card', async () => {
    mockFetch({ queue: () => json(200, [pendingItem()]) })
    render(<ApprovalQueuePage />)
    await screen.findByText('92%')

    const buttons = screen.getAllByRole('button')
    expect(buttons).toHaveLength(2)
    expect(
      screen.queryByText(/execute|block now|isolate now|disable now|run response/i),
    ).not.toBeInTheDocument()
  })

  it('deciding never touches /incidents or any endpoint besides the approval contract', async () => {
    const { calls } = mockFetch({
      queue: () => json(200, [pendingItem(), pendingItem({ id: 'rec-2', event_title: 'B' })]),
    })
    render(<ApprovalQueuePage />)
    const approveButtons = await screen.findAllByRole('button', { name: 'Approve' })
    fireEvent.click(approveButtons[0])
    await screen.findByText('1 pending')
    fireEvent.click(screen.getByRole('button', { name: 'Reject' }))
    await screen.findByText('No pending recommendations.')

    for (const call of calls) {
      expect(call.url).not.toContain('/incidents')
      expect(
        call.url === '/api/v1/approvals' ||
          call.url.startsWith('/api/v1/response-recommendations/'),
      ).toBe(true) // no event fetches, no recommendation re-fetch, no Shuffle
    }
  })
})
