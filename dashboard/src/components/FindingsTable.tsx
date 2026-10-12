import type { Finding } from '../types'
import { SeverityBadge } from './SeverityBadge'

// Rows are shown in the order the backend sent them (already sorted).
export function FindingsTable({ findings }: { findings: Finding[] }) {
  return (
    <section>
      <h2>Findings</h2>
      {findings.length === 0 ? (
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
              </tr>
            </thead>
            <tbody>
              {findings.map((f) => (
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
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
