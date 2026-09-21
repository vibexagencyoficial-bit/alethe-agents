import { ShieldCheck, ShieldX } from 'lucide-react'
import { useCallback, useEffect, useState } from 'react'

import { useT } from '../../lib/i18n'
import {
  controlPairingDecide,
  controlPairingPending,
  type ControlPairingRequest,
  type ControlPairingStatus,
  onControlPairingRequested,
} from '../../lib/tauri'
import styles from './ControlPairingConsent.module.css'

const POLL_MS = 3000

type Decision = { key: string; status: ControlPairingStatus }

function requestKey(request: ControlPairingRequest): string {
  return `${request.client_id}:${request.requested_at}`
}

/**
 * Consent prompt for the local control plane. It is not a modal on purpose: trapping focus
 * would block the whole window while a client waits, and the prompt must survive being
 * ignored until the request is decided or expires.
 */
export function ControlPairingConsent() {
  const t = useT()
  const [request, setRequest] = useState<ControlPairingRequest | null>(null)
  const [decision, setDecision] = useState<Decision | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [now, setNow] = useState(() => Math.floor(Date.now() / 1000))

  const refresh = useCallback(async () => {
    try {
      const pending = await controlPairingPending()
      setRequest(pending.pending ? pending : null)
      setError(null)
    } catch (value) {
      setError(String(value))
    }
  }, [])

  useEffect(() => {
    void refresh()
    const poll = window.setInterval(() => void refresh(), POLL_MS)
    const clock = window.setInterval(() => setNow(Math.floor(Date.now() / 1000)), 1000)
    return () => {
      window.clearInterval(poll)
      window.clearInterval(clock)
    }
  }, [refresh])

  useEffect(() => {
    let unlisten: (() => void) | undefined
    void onControlPairingRequested(() => void refresh()).then((stop) => {
      unlisten = stop
    })
    return () => unlisten?.()
  }, [refresh])

  const decide = async (approve: boolean) => {
    if (!request) return
    setBusy(true)
    try {
      const result = await controlPairingDecide(approve)
      setDecision({ key: requestKey(request), status: result.status })
      setError(null)
    } catch (value) {
      setError(String(value))
      void refresh()
    } finally {
      setBusy(false)
    }
  }

  if (!request) return null

  const decided = decision?.key === requestKey(request) ? decision.status : null
  const remaining = Math.max(0, request.expires_at - now)
  const expired = remaining === 0

  return (
    <section
      className={styles.card}
      role="alertdialog"
      aria-label={t('controlPairing.title')}
      data-control-pairing-consent=""
    >
      <header className={styles.header}>
        <span className={decided === 'denied' ? styles.iconDenied : styles.icon}>
          {decided === 'denied' ? <ShieldX size={18} /> : <ShieldCheck size={18} />}
        </span>
        <div>
          <h3>{t('controlPairing.title')}</h3>
          <p>{decided ? null : t('controlPairing.description')}</p>
        </div>
      </header>

      {decided ? (
        <p className={styles.outcome}>
          {decided === 'approved' ? t('controlPairing.approved') : t('controlPairing.denied')}
        </p>
      ) : (
        <>
          <div className={styles.clientRow}>
            <span className={styles.label}>{t('controlPairing.clientLabel')}</span>
            <code className={styles.client}>{request.client_id}</code>
          </div>
          <div className={styles.codeBlock}>
            <span className={styles.label}>{t('controlPairing.codeLabel')}</span>
            <code className={styles.code}>{request.code}</code>
            <span className={styles.countdown}>
              {t('controlPairing.countdown', { seconds: String(remaining) })}
            </span>
          </div>
          <p className={styles.warning}>{t('controlPairing.warning')}</p>
          <div className={styles.actions}>
            <button
              type="button"
              className={styles.deny}
              onClick={() => void decide(false)}
              disabled={busy || expired}
            >
              <ShieldX size={14} />
              {t('controlPairing.deny')}
            </button>
            <button
              type="button"
              className={styles.allow}
              onClick={() => void decide(true)}
              disabled={busy || expired}
            >
              <ShieldCheck size={14} />
              {t('controlPairing.allow')}
            </button>
          </div>
        </>
      )}

      {error ? <p className={styles.error}>{error}</p> : null}
    </section>
  )
}
