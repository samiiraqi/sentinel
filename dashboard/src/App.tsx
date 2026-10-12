import { useEffect, useState } from 'react'
import { fetchReport } from './api'
import { AgentStatusList } from './components/AgentStatusList'
import { FindingsTable } from './components/FindingsTable'
import { Summary } from './components/Summary'
import type { Report } from './types'
import './App.css'

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; report: Report }

function App() {
  const [state, setState] = useState<State>({ kind: 'loading' })

  useEffect(() => {
    const controller = new AbortController()
    fetchReport(controller.signal)
      .then((report) => setState({ kind: 'ready', report }))
      .catch((err: unknown) => {
        if (controller.signal.aborted) return
        setState({ kind: 'error', message: err instanceof Error ? err.message : 'Unknown error.' })
      })
    return () => controller.abort()
  }, [])

  return (
    <main>
      <h1>Sentinel Dashboard</h1>
      {state.kind === 'loading' && <p className="muted">Loading report…</p>}
      {state.kind === 'error' && (
        <p className="error" role="alert">
          {state.message}
        </p>
      )}
      {state.kind === 'ready' && (
        <>
          <p className="muted">
            Scanned: <code>{state.report.scanned_path}</code>
          </p>
          <Summary summary={state.report.summary} />
          <AgentStatusList agents={state.report.agents} />
          <FindingsTable findings={state.report.findings} />
        </>
      )}
    </main>
  )
}

export default App
