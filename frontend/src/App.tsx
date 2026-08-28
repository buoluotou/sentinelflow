/** Console router (Phase 1 Step 8): layout shell + business pages. */
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { ConsoleLayout } from './layouts/ConsoleLayout'
import { DashboardPage } from './pages/DashboardPage'
import { EventsPage } from './pages/EventsPage'
import { EventDetailPage } from './pages/EventDetailPage'
import { IncidentsPage } from './pages/IncidentsPage'
import { IncidentDetailPage } from './pages/IncidentDetailPage'
import { ApprovalQueuePage } from './pages/ApprovalQueuePage'
import { ExecutionAuditPage } from './pages/ExecutionAuditPage'
import { ExecutionDetailPage } from './pages/ExecutionDetailPage'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<ConsoleLayout />}>
          <Route index element={<DashboardPage />} />
          <Route path="events" element={<EventsPage />} />
          <Route path="events/:id" element={<EventDetailPage />} />
          <Route path="incidents" element={<IncidentsPage />} />
          <Route path="incidents/:id" element={<IncidentDetailPage />} />
          <Route path="approvals" element={<ApprovalQueuePage />} />
          <Route path="executions" element={<ExecutionAuditPage />} />
          <Route path="executions/:id" element={<ExecutionDetailPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
