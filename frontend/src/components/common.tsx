/** Shared presentational atoms used across console pages (Step 8.1). */
import type { ReactNode } from 'react'

/** Severity / risk-level chip; unknown values render a neutral chip. */
export function LevelBadge({ level }: { level: string | null | undefined }) {
  const cls = level && ['critical', 'high', 'medium', 'low'].includes(level) ? level : 'none'
  return <span className={`badge ${cls}`}>{level ?? '—'}</span>
}

/** Incident lifecycle chip; CSS class maps status -> colour. */
export function StatusBadge({ status }: { status: string }) {
  return <span className={`badge status-${status}`}>{status.replace('_', ' ')}</span>
}

/** ISO string -> local short form, stable across pages. */
export function formatTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString(undefined, {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
}

export function Loading() {
  return <p className="muted">Loading…</p>
}

export function ErrorBanner({ message }: { message: string }) {
  return <div className="error-banner">{message}</div>
}

export function Panel({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="panel">
      <h2>{title}</h2>
      {children}
    </section>
  )
}
