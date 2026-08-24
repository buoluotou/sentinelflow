import { useEffect, useState } from 'react'
import './App.css'

interface HealthStatus {
  status: string
  service: string
  database?: string
}

const roadmap = [
  { step: 'Step 1', name: '工程骨架', done: true },
  { step: 'Step 2', name: '数据模型 + Alert Ingestion', done: true },
  { step: 'Step 3', name: 'Alert Normalization', done: false },
  { step: 'Step 4', name: 'Deduplication / Aggregation', done: false },
  { step: 'Step 5', name: 'Scenario Simulator Runner', done: false },
  { step: 'Step 6', name: 'Incident Management', done: false },
  { step: 'Step 7', name: 'React Web Console', done: false },
]

function App() {
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/health')
      .then((res) => res.json() as Promise<HealthStatus>)
      .then(setHealth)
      .catch(() => setError('Backend unreachable'))
  }, [])

  return (
    <div className="app">
      <header>
        <h1>SentinelFlow Console</h1>
        <p>AI-assisted security alert orchestration &amp; incident response</p>
        <div className={`badge ${health ? 'ok' : 'down'}`}>
          {health
            ? `backend: ${health.status} · database: ${health.database ?? 'n/a'}`
            : (error ?? 'checking backend...')}
        </div>
      </header>

      <section>
        <h2>Phase 1 Roadmap</h2>
        <ul className="roadmap">
          {roadmap.map((item) => (
            <li key={item.step} className={item.done ? 'done' : ''}>
              <span className="step">{item.step}</span>
              <span>{item.name}</span>
              <span className="mark">{item.done ? '✅' : '⬜'}</span>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2>Console Pages (coming in Step 7)</h2>
        <p>
          Dashboard · Alerts · Alert Detail · Incidents · System Status
        </p>
      </section>
    </div>
  )
}

export default App
