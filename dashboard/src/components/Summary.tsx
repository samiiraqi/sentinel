import { SEVERITIES, type Report } from '../types'
import { SeverityBadge } from './SeverityBadge'

export function Summary({ summary }: { summary: Report['summary'] }) {
  return (
    <section className="cards" aria-label="Summary">
      <div className="card">
        <div className="card-label">total</div>
        <div className="card-value">{summary.total}</div>
      </div>
      {SEVERITIES.map((sev) => (
        <div className="card" key={sev}>
          <div className="card-label">
            <SeverityBadge severity={sev} />
          </div>
          <div className="card-value">{summary.by_severity[sev] ?? 0}</div>
        </div>
      ))}
    </section>
  )
}
