/** Console shell: fixed sidebar navigation + routed content area (Step 8.1). */
import { NavLink, Outlet } from 'react-router-dom'

const NAV_ITEMS = [
  { to: '/', label: 'Dashboard', end: true },
  { to: '/events', label: 'Events' },
  { to: '/incidents', label: 'Incidents' },
  { to: '/approvals', label: 'Approval Queue' },
  { to: '/executions', label: 'Execution Audit' },
]

export function ConsoleLayout() {
  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <h1>SentinelFlow</h1>
          <span>Security Operations</span>
        </div>
        <nav>
          {NAV_ITEMS.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end}>
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}
