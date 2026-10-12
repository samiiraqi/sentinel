import type { DecisionRecord } from './types'

export interface DecisionStatus {
  final: DecisionRecord | null // latest approve/reject record
  deferred: boolean // has a defer record but no final one
}

// Same rule as approval/decisions.py: only approve or reject counts as decided.
export function decisionStatus(records: DecisionRecord[]): Map<string, DecisionStatus> {
  const result = new Map<string, DecisionStatus>()
  for (const r of records) {
    const s = result.get(r.fingerprint) ?? { final: null, deferred: false }
    if (r.decision === 'approve' || r.decision === 'reject') s.final = r
    else if (r.decision === 'defer') s.deferred = true
    result.set(r.fingerprint, s)
  }
  for (const s of result.values()) {
    if (s.final) s.deferred = false
  }
  return result
}

// Show only the last two path segments, never a full /home/... path.
export function shortPath(path: string): string {
  return path.split(/[\\/]+/).filter(Boolean).slice(-2).join('/')
}
