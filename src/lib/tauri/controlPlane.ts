import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'

/** Pushed by the control plane when a client asks to pair; carries no secret. */
export const CONTROL_PAIRING_REQUESTED_EVENT = 'control://pairing/requested'

export type ControlPairingStatus = 'pending' | 'approved' | 'denied'

export type ControlPairingRequest = {
  pending: true
  client_id: string
  code: string
  status: ControlPairingStatus
  requested_at: number
  expires_at: number
  expires_in_seconds: number
}

export type ControlPairingPending = ControlPairingRequest | { pending: false; expired?: boolean }

export type ControlPairingDecision = {
  client_id: string
  status: ControlPairingStatus
  approved: boolean
}

/**
 * Reads the pending request, including the code. This is the only path the code travels:
 * it stays on the window side and is never part of an HTTP response, so a client cannot
 * read its own code and approve itself.
 */
export async function controlPairingPending(): Promise<ControlPairingPending> {
  return invoke<ControlPairingPending>('control_pairing_pending')
}

export async function controlPairingDecide(approve: boolean): Promise<ControlPairingDecision> {
  return invoke<ControlPairingDecision>('control_pairing_decide', { approve })
}

export function onControlPairingRequested(handler: () => void): Promise<UnlistenFn> {
  return listen(CONTROL_PAIRING_REQUESTED_EVENT, () => handler())
}
