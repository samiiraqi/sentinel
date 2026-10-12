import { useState } from 'react'
import { postDecision } from '../api'
import { DECISIONS, MAX_NOTE_CHARS, type DecisionKind, type DecisionRecord, type Finding } from '../types'

interface Props {
  finding: Finding
  onRecorded: (record: DecisionRecord) => void
}

export function DecisionControls({ finding, onRecorded }: Props) {
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function decide(decision: DecisionKind) {
    if (finding.severity === 'critical' && decision !== 'defer') {
      const ok = window.confirm(`This is a CRITICAL finding (${finding.rule_id}). Really ${decision} it?`)
      if (!ok) return
    }
    setBusy(true)
    setError(null)
    try {
      const record = await postDecision(finding.fingerprint, decision, note)
      // Update the UI only after the backend confirmed the decision.
      onRecorded(record)
      setNote('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="decide">
      <input
        type="text"
        className="note"
        placeholder="Optional note"
        aria-label={`Note for ${finding.rule_id} at ${finding.file}:${finding.line}`}
        maxLength={MAX_NOTE_CHARS}
        value={note}
        disabled={busy}
        onChange={(e) => setNote(e.target.value.slice(0, MAX_NOTE_CHARS))}
      />
      <div className="buttons">
        {DECISIONS.map((d) => (
          <button key={d} type="button" className={`btn btn-${d}`} disabled={busy} onClick={() => void decide(d)}>
            {d}
          </button>
        ))}
      </div>
      {busy && <div className="muted small">Saving…</div>}
      {error && (
        <div className="row-error" role="alert">
          {error}
        </div>
      )}
    </div>
  )
}
