/** Step 11.6: RiskSummaryPanel unit tests (jsdom, fetch mocked).
 *
 * Locks the frozen UI contract: GET-only on load (never an automatic POST),
 * 404 as a normal empty state, explicit trigger, backend 503/502 details
 * surfaced verbatim, and NO risk score ever rendered — EventRisk.score stays
 * the single official score even if a payload tried to smuggle one in.
 */
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { RiskSummaryPanel } from './RiskSummaryPanel'

const EVENT_ID = 'evt-1'
const URL = `/api/v1/events/${EVENT_ID}/ai-risk-summary`

/** Protocol-frozen sample payload; includes a smuggled risk_score to prove
 * the UI never renders one (backend rejects it, the UI must not either). */
function summaryBody(overrides: Record<string, unknown> = {}) {
  return {
    id: 'sum-1',
    alert_group_id: EVENT_ID,
    provider: 'ollama',
    model: 'qwen3:4b',
    summary: 'Repeated SSH authentication failures from a public source.',
    key_findings: ['Repeated login failures', 'External source', 'High frequency'],
    risk_drivers: ['authentication_abuse', 'high_frequency', 'severity'],
    analyst_priority: 'high',
    confidence: 0.95,
    created_at: '2026-08-26T02:59:01',
    updated_at: '2026-08-26T02:59:01',
    risk_score: 93, // must NEVER be rendered
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

describe('RiskSummaryPanel', () => {
  beforeEach(() => {
    vi.unstubAllGlobals()
  })
  afterEach(() => {
    cleanup() // vitest globals are off, so RTL's auto-cleanup never registers
    vi.unstubAllGlobals()
  })

  it('GET 200 on load renders the latest summary — and never POSTs on load', async () => {
    const fetchMock = mockFetch(() => json(200, summaryBody()))
    render(<RiskSummaryPanel eventId={EVENT_ID} />)

    expect(await screen.findByText('high')).toBeInTheDocument() // priority badge
    expect(screen.getByText('95%')).toBeInTheDocument() // confidence
    expect(
      screen.getByText('Repeated SSH authentication failures from a public source.'),
    ).toBeInTheDocument()
    expect(screen.getByText('Repeated login failures')).toBeInTheDocument()
    expect(screen.getByText('authentication_abuse')).toBeInTheDocument()
    expect(screen.getByText('high_frequency')).toBeInTheDocument()
    expect(screen.getByText('severity')).toBeInTheDocument()

    expect(fetchMock).toHaveBeenCalledTimes(1) // no second GET, no automatic POST
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(URL)
    expect((init?.method ?? 'GET').toUpperCase()).toBe('GET')
  })

  it('GET 404 is a normal empty state, not a system error', async () => {
    mockFetch(() => json(404, { detail: 'No AI risk summary recorded for this event' }))
    render(<RiskSummaryPanel eventId={EVENT_ID} />)

    expect(await screen.findByText('No risk summary generated yet.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /generate risk summary/i })).toBeEnabled()
    expect(document.querySelector('.error-banner')).toBeNull() // 404 is not red
  })

  it('clicking Generate triggers an explicit POST', async () => {
    const fetchMock = mockFetch(
      () => json(404, { detail: 'No AI risk summary recorded for this event' }),
      () => json(201, summaryBody({ id: 'sum-2' })),
    )
    render(<RiskSummaryPanel eventId={EVENT_ID} />)
    fireEvent.click(await screen.findByRole('button', { name: /generate risk summary/i }))

    await waitFor(() => {
      const postCalls = fetchMock.mock.calls.filter(
        ([, init]) => (init?.method ?? 'GET').toUpperCase() === 'POST',
      )
      expect(postCalls).toHaveLength(1)
      expect(postCalls[0][0]).toBe(URL)
    })
  })

  it('POST 201 renders the new summary from the response body (no extra GET)', async () => {
    const fetchMock = mockFetch(
      () => json(404, { detail: 'No AI risk summary recorded for this event' }),
      () => json(201, summaryBody({ id: 'sum-2', summary: 'Fresh summary from the model.' })),
    )
    render(<RiskSummaryPanel eventId={EVENT_ID} />)
    fireEvent.click(await screen.findByRole('button', { name: /generate risk summary/i }))

    expect(await screen.findByText('Fresh summary from the model.')).toBeInTheDocument()
    expect(fetchMock).toHaveBeenCalledTimes(2) // GET + POST, no follow-up GET
  })

  it('POST 503 surfaces the backend detail verbatim', async () => {
    mockFetch(
      () => json(404, { detail: 'No AI risk summary recorded for this event' }),
      () => json(503, { detail: 'AI provider unavailable: Cannot reach Ollama' }),
    )
    render(<RiskSummaryPanel eventId={EVENT_ID} />)
    fireEvent.click(await screen.findByRole('button', { name: /generate risk summary/i }))

    expect(
      await screen.findByText('AI provider unavailable: Cannot reach Ollama'),
    ).toBeInTheDocument()
    expect(screen.getByText('No risk summary generated yet.')).toBeInTheDocument()
  })

  it('POST 502 surfaces the protocol-violation detail verbatim', async () => {
    mockFetch(
      () => json(404, { detail: 'No AI risk summary recorded for this event' }),
      () =>
        json(502, {
          detail: 'AI response did not match the expected protocol: bad JSON',
        }),
    )
    render(<RiskSummaryPanel eventId={EVENT_ID} />)
    fireEvent.click(await screen.findByRole('button', { name: /generate risk summary/i }))

    expect(
      await screen.findByText('AI response did not match the expected protocol: bad JSON'),
    ).toBeInTheDocument()
  })

  it('button is disabled while a POST is in flight (no stacked requests)', async () => {
    let resolvePost!: (value: Response) => void
    const pendingPost = new Promise<Response>((resolve) => {
      resolvePost = resolve
    })
    const fetchMock = mockFetch(
      () => json(404, { detail: 'No AI risk summary recorded for this event' }),
      () => pendingPost,
    )
    render(<RiskSummaryPanel eventId={EVENT_ID} />)

    const button = await screen.findByRole('button', { name: /generate risk summary/i })
    fireEvent.click(button)
    await screen.findByText('Generating risk summary…')
    expect(button).toBeDisabled()

    fireEvent.click(button) // double click must not stack a second POST
    resolvePost(json(201, summaryBody({ id: 'sum-2' })))
    await screen.findByText('Repeated SSH authentication failures from a public source.')

    const postCalls = fetchMock.mock.calls.filter(
      ([, init]) => (init?.method ?? 'GET').toUpperCase() === 'POST',
    )
    expect(postCalls).toHaveLength(1)
  })

  it('never renders a risk score, even when the payload smuggles one in', async () => {
    mockFetch(() => json(200, summaryBody()))
    render(<RiskSummaryPanel eventId={EVENT_ID} />)
    await screen.findByText('95%')

    expect(screen.queryByText(/risk score/i)).not.toBeInTheDocument()
    expect(screen.queryByText('93')).not.toBeInTheDocument()
  })
})
