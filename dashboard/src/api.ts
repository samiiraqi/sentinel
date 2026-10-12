import type { Report } from './types'

// Fixed on purpose: never taken from user input or the page URL.
export const BACKEND_URL = 'http://127.0.0.1:8000'

export async function fetchReport(signal: AbortSignal): Promise<Report> {
  let resp: Response
  try {
    resp = await fetch(`${BACKEND_URL}/report`, { method: 'GET', signal })
  } catch (err) {
    if (signal.aborted) throw err
    throw new Error(`Cannot reach the backend at ${BACKEND_URL}. Is it running? (python -m backend)`)
  }
  if (!resp.ok) {
    throw new Error(`Backend returned HTTP ${resp.status}.`)
  }
  const data: unknown = await resp.json()
  if (!isReport(data)) {
    throw new Error('Backend sent a report in an unexpected format.')
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
