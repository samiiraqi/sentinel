import { useState } from 'react'
import type { DecisionStatus } from '../decisions'
import type { DecisionRecord, Finding } from '../types'
import { DecisionControls } from './DecisionControls'
import { SeverityBadge } from './SeverityBadge'

type Filter = 'all' | 'pending' | 'decided'
const FILTERS: Filter[] = ['all', 'pending', 'decided']

interface Props {
  findings: Finding[]
  status: Map<string, DecisionStatus>
  onRecorded: (record: DecisionRecord) => void
}

// Rows are shown in the order the backend sent them (already sorted).
export function FindingsTable({ findings, status, onRecorded }: Props) {
  const [filter, setFilter] = useState<Filter>('all')
  const isDecided = (f: Finding) => Boolean(status.get(f.fingerprint)?.final)
  const counts = {
    all: findings.length,
    decided: findings.filter(isDecided).length,
    pending: findings.filter((f) => !isDecided(f)).length,
  }
  const shown = findings.filter((f) =>
    filter === 'all' ? true : filter === 'decided' ? isDecided(f) : !isDecided(f),
  )

  return (
    <section>
      <h2>Findings</h2>
      <div className="filters" role="group" aria-label="Filter findings">
        {FILTERS.map((f) => (
          <button
            key={f}
            type="button"
            className={filter === f ? 'filter active' : 'filter'}
            aria-pressed={filter === f}
            onClick={() => setFilter(f)}
          >
            {f} ({counts[f]})
          </button>
        ))}
      </div>
      {shown.length === 0 ? (
        <p>No findings.</p>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Severity</th>
                <th>Agent</th>
                <th>Rule</th>
                <th>Location</th>
                <th>Match (redacted)</th>
                <th>Decision</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((f) => {
                const s = status.get(f.fingerprint)
                return (
                  <tr key={f.fingerprint}>
                    <td>
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td>{f.agent}</td>
                    <td>
                      <code>{f.rule_id}</code>
                    </td>
                    <td>
                      <code>
                        {f.file}:{f.line}
                      </code>
                    </td>
                    <td>
                      <code>{f.redacted_match}</code>
                    </td>
                    <td>
                      {s?.final ? (
                        <div>
                          <span className={`decided decided-${s.final.decision}`}>
                            {s.final.decision === 'approve' ? 'approved' : 'rejected'}
                          </span>{' '}
                          <span className="muted small">by {s.final.approver}</span>
                          {s.final.note && <div className="muted small">“{s.final.note}”</div>}
                        </div>
                      ) : (
                        <>
                          {s?.deferred && <span className="deferred">deferred</span>}
                          <DecisionControls finding={f} onRecorded={onRecorded} />
                        </>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
