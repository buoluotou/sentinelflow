/** Step 12.5: ResponseRecommendationPanel unit tests (jsdom, fetch mocked).
 *
 * Locks the frozen UI contract: GET-only on load (never an automatic POST),
 * 404 as a normal empty state DISTINCT from 200 + recommendations=[] ("no
 * action warranted" is a success), explicit trigger, backend 503/502 details
 * surfaced verbatim, no risk score ever rendered, and NO execution
 * affordance — the only button is Generate.
 */
import { cleanup, fireEvent, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { ResponseRecommendationPanel } from './ResponseRecommendationPanel'

const EVENT_ID = 'evt-1'
const URL = `/api/v1/events/${EVENT_ID}/response-recommendation`

const SIX_ACTIONS = [
  'block_source_ip',
  'isolate_host',
  'disable_account',
  'hunt_related_activity',
  'escalate_to_incident',
  'monitor_only',
] as const

/** Protocol-frozen sample payload; includes a smuggled risk_score to prove
 * the UI never renders one (backend rejects it, the UI must not either). */
function recommendationBody(overrides: Record<string, unknown> = {}) {
  return {
    id: 'rec-1',
    alert_group_id: EVENT_ID,
    provider: 'ollama',
    model: 'qwen3:4b',
    overall_rationale:
      'Repeated external authentication failures suggest coordinated response.',
    recommendations: [
      {
        action: 'block_source_ip',
        target: '203.0.113.10',
        rationale: 'Repeated authentication abuse from this source.',
      },
      {
        action: 'escalate_to_incident',
        target: 'Authentication event',
        rationale: 'High-risk activity warrants incident tracking.',
      },
    ],
    confidence: 0.92,
    created_at: '2026-08-26T02:59:01',
    updated_at: '2026-08-26T02:59:01',
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

/** Route fetch by method: [getResponse, postResponse]. */
function mockFetch(get: () => Response, post?: () => Response | Promise<Response>) {
  const fn = vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
    const method = (init?.method ?? 'GET').toUpperCase()
    if (method === 'POST' && post) return post()
    return get()
  })
  vi.stubGlobal('fetch', fn)
  return fn
}

describe('ResponseRecommendationPanel', () => {
  beforeEach(() => {
    vi.unstubAllGlobals()
  })
  afterEach(() => {
    cleanup() // vitest globals are off, so RTL's auto-cleanup never registered
    vi.unstubAllGlobals()
  })

  it('GET 200 on load renders the latest recommendation — and never POSTs on load', async () => {
    const fetchMock = mockFetch(() => json(200, recommendationBody()))
    render(<ResponseRecommendationPanel eventId={EVENT_ID} />)

    expect(
      await screen.findByText(
        'Repeated external authentication failures suggest coordinated response.',
      ),
    ).toBeInTheDocument()
    expect(screen.getByText('Block Source IP')).toBeInTheDocument()
    expect(screen.getByText('Escalate to Incident')).toBeInTheDocument()
    expect(screen.getByText('203.0.113.10')).toBeInTheDocument()
    expect(
      screen.getByText('Rationale: Repeated authentication abuse from this source.'),
    ).toBeInTheDocument()
    expect(
      screen.getByText('Rationale: High-risk activity warrants incident tracking.'),
    ).toBeInTheDocument()
    expect(screen.getByText('92%')).toBeInTheDocument()

    expect(fetchMock).toHaveBeenCalledTimes(1) // no second GET, no automatic POST
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(URL)
    expect((init?.method ?? 'GET').toUpperCase()).toBe('GET')
  })

  it('renders all six frozen actions with readable labels', async () => {
    const items = SIX_ACTIONS.map((action) => ({
      action,
      target: 'host-1',
      rationale: `rationale for ${action}`,
    }))
    mockFetch(() => json(200, recommendationBody({ recommendations: items })))
    render(<ResponseRecommendationPanel eventId={EVENT_ID} />)

    expect(await screen.findByText('Block Source IP')).toBeInTheDocument()
    expect(screen.getByText('Isolate Host')).toBeInTheDocument()
    expect(screen.getByText('Disable Account')).toBeInTheDocument()
    expect(screen.getByText('Hunt Related Activity')).toBeInTheDocument()
    expect(screen.getByText('Escalate to Incident')).toBeInTheDocument()
    expect(screen.getByText('Monitor Only')).toBeInTheDocument()
  })

  it('GET 404 is a normal empty state, not a system error', async () => {
    mockFetch(() =>
      json(404, { detail: 'No response recommendation recorded for this event' }),
    )
    render(<ResponseRecommendationPanel eventId={EVENT_ID} />)

    expect(await screen.findByText('No recommendation generated yet.')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: /generate response recommendation/i }),
    ).toBeEnabled()
    expect(document.querySelector('.error-banner')).toBeNull() // 404 is not red
  })

  it('200 + recommendations=[] is "no action warranted" — NOT the 404 empty state', async () => {
    mockFetch(() => json(200, recommendationBody({ recommendations: [] })))
    render(<ResponseRecommendationPanel eventId={EVENT_ID} />)

    expect(await screen.findByText('No response action warranted.')).toBeInTheDocument()
    expect(
      screen.queryByText('No recommendation generated yet.'),
    ).not.toBeInTheDocument()
    expect(document.querySelector('.error-banner')).toBeNull() // success, not error
  })

  it('clicking Generate triggers an explicit POST', async () => {
    const fetchMock = mockFetch(
      () =>
        json(404, { detail: 'No response recommendation recorded for this event' }),
      () => json(201, recommendationBody({ id: 'rec-2' })),
    )
    render(<ResponseRecommendationPanel eventId={EVENT_ID} />)
    fireEvent.click(
      await screen.findByRole('button', { name: /generate response recommendation/i }),
    )

    const postCalls = fetchMock.mock.calls.filter(
      ([, init]) => (init?.method ?? 'GET').toUpperCase() === 'POST',
    )
    expect(postCalls).toHaveLength(1)
    expect(postCalls[0][0]).toBe(URL)
  })

  it('POST 201 renders the new recommendation from the response body (no extra GET)', async () => {
    const fetchMock = mockFetch(
      () =>
        json(404, { detail: 'No response recommendation recorded for this event' }),
      () =>
        json(
          201,
          recommendationBody({
            id: 'rec-2',
            overall_rationale: 'Fresh advice from the model.',
          }),
        ),
    )
    render(<ResponseRecommendationPanel eventId={EVENT_ID} />)
    fireEvent.click(
      await screen.findByRole('button', { name: /generate response recommendation/i }),
    )

    expect(await screen.findByText('Fresh advice from the model.')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(2) // GET + POST, no follow-up GET
  })

  it('button is disabled while a POST is in flight (no stacked requests)', async () => {
    let resolvePost!: (value: Response) => void
    const pendingPost = new Promise<Response>((resolve) => {
      resolvePost = resolve
    })
    const fetchMock = mockFetch(
      () =>
        json(404, { detail: 'No response recommendation recorded for this event' }),
      () => pendingPost,
    )
    render(<ResponseRecommendationPanel eventId={EVENT_ID} />)

    const button = await screen.findByRole('button', {
      name: /generate response recommendation/i,
    })
    fireEvent.click(button)
    await screen.findByText('Generating response recommendation…')
    expect(button).toBeDisabled()

    fireEvent.click(button) // double click must not stack a second POST
    resolvePost(json(201, recommendationBody({ id: 'rec-2' })))
    await screen.findByText(
      'Repeated external authentication failures suggest coordinated response.',
    )

    const postCalls = fetchMock.mock.calls.filter(
      ([, init]) => (init?.method ?? 'GET').toUpperCase() === 'POST',
    )
    expect(postCalls).toHaveLength(1)
  })

  it('POST 503 surfaces the backend detail verbatim', async () => {
    mockFetch(
      () =>
        json(404, { detail: 'No response recommendation recorded for this event' }),
      () => json(503, { detail: 'AI provider unavailable: Cannot reach Ollama' }),
    )
    render(<ResponseRecommendationPanel eventId={EVENT_ID} />)
    fireEvent.click(
      await screen.findByRole('button', { name: /generate response recommendation/i }),
    )

    expect(
      await screen.findByText('AI provider unavailable: Cannot reach Ollama'),
    ).toBeInTheDocument()
    expect(screen.getByText('No recommendation generated yet.')).toBeInTheDocument()
  })

  it('POST 502 surfaces the protocol-violation detail verbatim', async () => {
    mockFetch(
      () =>
        json(404, { detail: 'No response recommendation recorded for this event' }),
      () =>
        json(502, {
          detail: 'AI response did not match the expected protocol: bad JSON',
        }),
    )
    render(<ResponseRecommendationPanel eventId={EVENT_ID} />)
    fireEvent.click(
      await screen.findByRole('button', { name: /generate response recommendation/i }),
    )

    expect(
      await screen.findByText('AI response did not match the expected protocol: bad JSON'),
    ).toBeInTheDocument()
  })

  it('never renders a risk score, even when the payload smuggles one in', async () => {
    mockFetch(() => json(200, recommendationBody()))
    render(<ResponseRecommendationPanel eventId={EVENT_ID} />)
    await screen.findByText('92%')

    expect(screen.queryByText(/risk score/i)).not.toBeInTheDocument()
    expect(screen.queryByText('88')).not.toBeInTheDocument()
  })

  it('renders no execution affordance — Generate is the only button', async () => {
    mockFetch(() => json(200, recommendationBody()))
    render(<ResponseRecommendationPanel eventId={EVENT_ID} />)
    await screen.findByText('92%')

    const buttons = screen.getAllByRole('button')
    expect(buttons).toHaveLength(1)
    expect(buttons[0]).toHaveTextContent('Generate Response Recommendation')
    // No executor labels anywhere in the panel (advisory-only boundary).
    expect(
      screen.queryByText(/execute|block now|run response|apply action/i),
    ).not.toBeInTheDocument()
  })
})
