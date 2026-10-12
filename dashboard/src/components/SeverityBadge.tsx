import { SEVERITIES, type Severity } from '../types'

export function SeverityBadge({ severity }: { severity: Severity }) {
  // Only known severities become a CSS class; anything else is shown as "unknown".
  const known = SEVERITIES.includes(severity)
  return <span className={`badge badge-${known ? severity : 'unknown'}`}>{known ? severity : 'unknown'}</span>
}
