import type { DecisionKind, DecisionRecord, Report } from './types'

// Fixed on purpose: never taken from user input or the page URL.
export const BACKEND_URL = 'http://127.0.0.1:8000'

async function request(path: string, init: RequestInit): Promise<unknown> {
  let resp: Response
  try {
    resp = await fetch(`${BACKEND_URL}${path}`, init)
  } catch (err) {
    if (init.signal?.aborted) throw err
    throw new Error(`Cannot reach the backend at ${BACKEND_URL}. Is it running? (python -m backend)`)
  }
  if (resp.status === 404 && path === '/decisions') {
    throw new Error('This finding is not in the latest scan any more. Reload the page.')
  }
  if (resp.status === 422) {
    throw new Error('The backend rejected the request as invalid.')
  }
  if (!resp.ok) {
    throw new Error(`Backend returned HTTP ${resp.status}.`)
  }
  return resp.json()
}

export async function fetchReport(signal: AbortSignal): Promise<Report> {
  const data = await request('/report', { method: 'GET', signal })
  if (!isReport(data)) {
    throw new Error('Backend sent a report in an unexpected format.')
  }
  return data
}

export async function fetchDecisions(signal: AbortSignal): Promise<DecisionRecord[]> {
  const data = await request('/decisions', { method: 'GET', signal })
  if (!Array.isArray(data) || !data.every(isDecisionRecord)) {
    throw new Error('Backend sent decisions in an unexpected format.')
  }
  return data
}

// Sends ONLY fingerprint, decision and note. The approver is set by the server.
export async function postDecision(
  fingerprint: string,
  decision: DecisionKind,
  note: string,
): Promise<DecisionRecord> {
  const data = await request('/decisions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fingerprint, decision, note }),
  })
  if (!isDecisionRecord(data)) {
    throw new Error('Backend sent a decision in an unexpected format.')
  }
  return data
}

function isReport(data: unknown): data is Report {
  if (typeof data !== 'object' || data === null) return false
  const r = data as Partial<Report>
  return (
    typeof r.scanned_path === 'string' &&
    typeof r.agents === 'object' && r.agents !== null &&
    typeof r.summary === 'object' && r.summary !== null &&
    Array.isArray(r.findings)
  )
}

function isDecisionRecord(data: unknown): data is DecisionRecord {
  if (typeof data !== 'object' || data === null) return false
  const r = data as Partial<DecisionRecord>
  return typeof r.fingerprint === 'string' && typeof r.decision === 'string' && typeof r.approver === 'string'
}
