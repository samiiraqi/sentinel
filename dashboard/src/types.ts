// Shape of GET /report from the Sentinel backend (see orchestrator/orchestrator.py).

export const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const
export type Severity = (typeof SEVERITIES)[number]

export interface Finding {
  agent: string
  rule_id: string
  severity: Severity
  file: string
  line: number
  message: string
  redacted_match: string
  fingerprint: string
}

export interface AgentStatus {
  status: 'ok' | 'failed'
  error: string | null
  count: number
}

export interface Report {
  scanned_path: string
  agents: Record<string, AgentStatus>
  summary: {
    total: number
    by_severity: Record<Severity, number>
    by_agent: Record<string, number>
  }
  findings: Finding[]
}

export const DECISIONS = ['approve', 'reject', 'defer'] as const
export type DecisionKind = (typeof DECISIONS)[number]

// One line of the audit log, as returned by GET /decisions and POST /decisions.
export interface DecisionRecord {
  timestamp: string
  fingerprint: string
  decision: DecisionKind
  approver: string
  note: string
}

// Same limit as MAX_NOTE_CHARS in backend/app.py.
export const MAX_NOTE_CHARS = 500
