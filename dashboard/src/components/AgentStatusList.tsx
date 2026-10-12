import type { Report } from '../types'

export function AgentStatusList({ agents }: { agents: Report['agents'] }) {
  return (
    <section>
      <h2>Agents</h2>
      <ul className="agents">
        {Object.entries(agents).map(([name, info]) => (
          <li key={name}>
            <span className={info.status === 'ok' ? 'status status-ok' : 'status status-failed'}>
              {info.status === 'ok' ? 'ok' : 'failed'}
            </span>{' '}
            <strong>{name}</strong> — {info.count} finding(s)
            {info.error && <div className="agent-error">{info.error}</div>}
          </li>
        ))}
      </ul>
    </section>
  )
}
