/** Step 14.5: IncidentAIContextPanel unit tests (jsdom, fetch mocked).
 *
 * Locks the frozen UI contract of the read-only incident AI view:
 *   A. a full context renders snapshot + every history section
 *   B. multiple history rows all render — never "latest only"
 *   C. approved / rejected / pending (approval=null) approval states
 *   D. all-empty histories are a legal empty state, not an error
 *   E. a partial pipeline (analyses only) still renders cleanly
 *   F. safety boundary: no Execute/Block Now/Isolate Now/... affordance,
 *      no Approve/Reject buttons, GET-only — exactly one fetch, correct URL
 *   G. only risk_score_snapshot is shown; the UI never recomputes risk
 */
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { IncidentAIContextPanel } from './IncidentAIContextPanel'

const INCIDENT_ID = 'inc-1'
const GROUP_ID = 'grp-1'
const URL = `/api/v1/incidents/${INCIDENT_ID}/ai-context`

function analysisBody(n: number, overrides: Record<string, unknown> = {}) {
  return {
    id: `ana-${n}`,
    alert_group_id: GROUP_ID,
    provider: 'mock',
    model: 'mock-model',
    summary: `Analysis summary ${n}`,
    attack_type: 'brute_force',
    why_risky: ['high failure rate'],
    confidence: 0.9,
    created_at: `2026-08-27T08:0${n}:00`,
    ...overrides,
  }
}

function summaryBody(n: number, overrides: Record<string, unknown> = {}) {
  return {
    id: `sum-${n}`,
    alert_group_id: GROUP_ID,
    provider: 'mock',
    model: 'mock-model',
    summary: `Risk summary ${n}`,
    key_findings: [`finding ${n}`],
    risk_drivers: ['severity'],
    analyst_priority: 'high',
    confidence: 0.88,
    created_at: `2026-08-27T09:0${n}:00`,
    updated_at: `2026-08-27T09:0${n}:00`,
    ...overrides,
  }
}

function recommendationBody(
  n: number,
  approval: Record<string, unknown> | null,
  overrides: Record<string, unknown> = {},
) {
  return {
    recommendation: {
      id: `rec-${n}`,
      alert_group_id: GROUP_ID,
      provider: 'mock',
      model: 'mock-model',
      overall_rationale: `Rationale ${n}`,
      recommendations: [
        { action: 'block_source_ip', target: '203.0.113.10', rationale: 'abuse' },
      ],
      confidence: 0.92,
      created_at: `2026-08-27T10:0${n}:00`,
      updated_at: `2026-08-27T10:0${n}:00`,
      ...overrides,
    },
    approval,
  }
}

function approvalBody(n: number, status: 'approved' | 'rejected') {
  return {
    id: `apr-${n}`,
    recommendation_id: `rec-${n}`,
    status,
    reviewer: 'alice',
    reviewed_at: '2026-08-27T11:00:00',
    review_comment: 'confirmed',
    created_at: '2026-08-27T11:00:00',
    updated_at: '2026-08-27T11:00:00',
  }
}

function contextBody(overrides: Record<string, unknown> = {}) {
  return {
    incident: {
      id: INCIDENT_ID,
      status: 'open',
      severity: 'high',
      risk_score_snapshot: 80,
    },
    analyses: [],
    risk_summaries: [],
    response_recommendations: [],
    ...overrides,
  }
}

function mockFetch(response: () => Response) {
  const fn = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => response())
  vi.stubGlobal('fetch', fn)
  return fn
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

describe('IncidentAIContextPanel', () => {
  beforeEach(() => {
    vi.unstubAllGlobals()
  })
  afterEach(() => {
    cleanup() // vitest globals are off, so RTL's auto-cleanup never registers
    vi.unstubAllGlobals()
  })

  it('A. renders the snapshot and every history section of a full context', async () => {
    mockFetch(() =>
      json(
        200,
        contextBody({
          analyses: [analysisBody(1)],
          risk_summaries: [summaryBody(1)],
          response_recommendations: [recommendationBody(1, approvalBody(1, 'approved'))],
        }),
      ),
    )
    render(<IncidentAIContextPanel incidentId={INCIDENT_ID} />)

    expect(await screen.findByText('Analysis summary 1')).toBeInTheDocument()
    expect(screen.getByText('Risk summary 1')).toBeInTheDocument()
    expect(screen.getByText('Rationale 1')).toBeInTheDocument()
    expect(screen.getByText('Block Source IP')).toBeInTheDocument() // display label
    expect(screen.getByText('203.0.113.10')).toBeInTheDocument()
    expect(screen.getByText('Approved')).toBeInTheDocument()
    expect(screen.getByText('alice')).toBeInTheDocument()
    expect(screen.getByText(/AI Explanation History \(1\)/)).toBeInTheDocument()
    expect(screen.getByText(/Risk Summary History \(1\)/)).toBeInTheDocument()
    expect(screen.getByText(/Response Recommendation History \(1\)/)).toBeInTheDocument()
  })

  it('B. renders EVERY history row — never only the latest', async () => {
    mockFetch(() =>
      json(
        200,
        contextBody({
          analyses: [analysisBody(1), analysisBody(2)],
          risk_summaries: [summaryBody(1), summaryBody(2)],
          response_recommendations: [
            recommendationBody(1, approvalBody(1, 'approved')),
            recommendationBody(2, approvalBody(2, 'rejected')),
            recommendationBody(3, null),
          ],
        }),
      ),
    )
    render(<IncidentAIContextPanel incidentId={INCIDENT_ID} />)

    expect(await screen.findByText('Analysis summary 1')).toBeInTheDocument()
    expect(screen.getByText('Analysis summary 2')).toBeInTheDocument()
    expect(screen.getByText('Risk summary 1')).toBeInTheDocument()
    expect(screen.getByText('Risk summary 2')).toBeInTheDocument()
    expect(screen.getByText('Rationale 1')).toBeInTheDocument()
    expect(screen.getByText('Rationale 2')).toBeInTheDocument()
    expect(screen.getByText('Rationale 3')).toBeInTheDocument()
    expect(screen.getByText(/AI Explanation History \(2\)/)).toBeInTheDocument()
    expect(screen.getByText(/Response Recommendation History \(3\)/)).toBeInTheDocument()
  })

  it('C. renders approved / rejected / pending — pending derives from approval=null', async () => {
    mockFetch(() =>
      json(
        200,
        contextBody({
          response_recommendations: [
            recommendationBody(1, approvalBody(1, 'approved')),
            recommendationBody(2, approvalBody(2, 'rejected')),
            recommendationBody(3, null),
          ],
        }),
      ),
    )
    render(<IncidentAIContextPanel incidentId={INCIDENT_ID} />)

    expect(await screen.findByText('Approved')).toBeInTheDocument()
    expect(screen.getByText('Rejected')).toBeInTheDocument()
    expect(screen.getByText('Pending Review')).toBeInTheDocument()
    // Pending is a display derivation — no "pending" status text anywhere else.
    expect(screen.queryByText(/^pending$/i)).not.toBeInTheDocument()
  })

  it('D. all-empty histories are a legal empty state, not an error', async () => {
    mockFetch(() => json(200, contextBody()))
    render(<IncidentAIContextPanel incidentId={INCIDENT_ID} />)

    expect(await screen.findByText('No AI analysis available yet.')).toBeInTheDocument()
    expect(document.querySelector('.error-banner')).toBeNull()
  })

  it('E. a partial pipeline (analyses only) renders without assuming later stages', async () => {
    mockFetch(() => json(200, contextBody({ analyses: [analysisBody(1)] })))
    render(<IncidentAIContextPanel incidentId={INCIDENT_ID} />)

    expect(await screen.findByText('Analysis summary 1')).toBeInTheDocument()
    expect(screen.queryByText(/Risk Summary History/)).not.toBeInTheDocument()
    expect(screen.queryByText(/Response Recommendation History/)).not.toBeInTheDocument()
    expect(document.querySelector('.error-banner')).toBeNull()
  })

  it('F. safety boundary: zero execution or decision affordances, GET-only', async () => {
    const fetchMock = mockFetch(() =>
      json(
        200,
        contextBody({
          analyses: [analysisBody(1)],
          risk_summaries: [summaryBody(1)],
          response_recommendations: [recommendationBody(1, approvalBody(1, 'approved'))],
        }),
      ),
    )
    render(<IncidentAIContextPanel incidentId={INCIDENT_ID} />)
    await screen.findByText('Approved')

    // No execution entry point of any kind in the rendered DOM.
    const text = document.body.textContent ?? ''
    for (const forbidden of [
      /execute/i,
      /block now/i,
      /isolate now/i,
      /disable now/i,
      /run response/i,
      /retry/i,
    ]) {
      expect(text).not.toMatch(forbidden)
    }
    // And no buttons at all: no Approve/Reject (Approval Queue owns decisions)
    // and nothing else clickable inside this read-only panel.
    expect(screen.queryAllByRole('button')).toHaveLength(0)

    // Exactly one network call, GET, against the frozen read-only endpoint.
    expect(fetchMock).toHaveBeenCalledTimes(1)
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe(URL)
    expect((init?.method ?? 'GET').toUpperCase()).toBe('GET')
  })

  it('G. shows only the risk_score_snapshot — never a recomputed score', async () => {
    mockFetch(() => json(200, contextBody()))
    render(<IncidentAIContextPanel incidentId={INCIDENT_ID} />)

    expect(await screen.findByText('80')).toBeInTheDocument()
    expect(screen.getByText(/Risk Score \(snapshot\):/)).toBeInTheDocument()
    // No smuggled live score concept in the panel.
    expect((document.body.textContent ?? '').toLowerCase()).not.toContain('live score')
  })

  it('surfaces a 404 backend detail verbatim as an error banner', async () => {
    mockFetch(() => json(404, { detail: 'Incident not found' }))
    render(<IncidentAIContextPanel incidentId={INCIDENT_ID} />)

    expect(await screen.findByText('Incident not found')).toBeInTheDocument()
    expect(document.querySelector('.error-banner')).not.toBeNull()
  })
})
