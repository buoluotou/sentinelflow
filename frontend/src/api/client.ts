/**
 * Minimal API client for the SentinelFlow backend (Phase 1 Step 8.1).
 *
 * All console pages go through this layer: React -> api client -> FastAPI.
 * Pages never assemble database fields or business rules themselves.
 * The dev server proxies /api to the backend (see vite.config.ts).
 */

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`/api/v1${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })
  if (!res.ok) {
    // FastAPI error bodies carry { detail: "..." } — surface it verbatim.
    let detail = `HTTP ${res.status}`
    try {
      const body = (await res.json()) as { detail?: unknown }
      if (typeof body.detail === 'string') detail = body.detail
    } catch {
      /* non-JSON body: keep the generic message */
    }
    throw new ApiError(res.status, detail)
  }
  return (await res.json()) as T
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body: unknown) =>
    request<T>(path, { method: 'POST', body: JSON.stringify(body) }),
  patch: <T>(path: string, body: unknown) =>
    request<T>(path, { method: 'PATCH', body: JSON.stringify(body) }),
}

/** Build a query string from defined params only (skips null/undefined). */
export function queryString(params: Record<string, string | number | undefined>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) search.set(key, String(value))
  }
  const qs = search.toString()
  return qs ? `?${qs}` : ''
}
