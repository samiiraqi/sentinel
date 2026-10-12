import { useEffect, useMemo, useState } from 'react'
import { fetchDecisions, fetchReport } from './api'
import { AgentStatusList } from './components/AgentStatusList'
import { FindingsTable } from './components/FindingsTable'
import { Summary } from './components/Summary'
import { decisionStatus, shortPath } from './decisions'
import type { DecisionRecord, Report } from './types'
import './App.css'

type State =
  | { kind: 'loading' }
  | { kind: 'error'; message: string }
  | { kind: 'ready'; report: Report }

function App() {
  const [state, setState] = useState<State>({ kind: 'loading' })
  const [decisions, setDecisions] = useState<DecisionRecord[]>([])
  const status = useMemo(() => decisionStatus(decisions), [decisions])

  useEffect(() => {
    const controller = new AbortController()
    Promise.all([fetchReport(controller.signal), fetchDecisions(controller.signal)])
      .then(([report, records]) => {
        setDecisions(records)
        setState({ kind: 'ready', report })
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return
        setState({ kind: 'error', message: err instanceof Error ? err.message : 'Unknown error.' })
      })
    return () => controller.abort()
  }, [])

  // Called only with the record the backend returned after a successful POST.
  const onRecorded = (record: DecisionRecord) => setDecisions((prev) => [...prev, record])

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
            Scanned: <code>{shortPath(state.report.scanned_path)}</code>
          </p>
          <Summary summary={state.report.summary} />
          <AgentStatusList agents={state.report.agents} />
          <FindingsTable findings={state.report.findings} status={status} onRecorded={onRecorded} />
        </>
      )}
    </main>
  )
}

export default App
