import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

const tauri = vi.hoisted(() => ({
  controlPairingPending: vi.fn(),
  controlPairingDecide: vi.fn(),
  onControlPairingRequested: vi.fn(),
  requestHandler: null as null | (() => void),
}))

vi.mock('../../lib/tauri', () => ({
  controlPairingPending: tauri.controlPairingPending,
  controlPairingDecide: tauri.controlPairingDecide,
  onControlPairingRequested: tauri.onControlPairingRequested,
}))

vi.mock('../../stores/projectsStore', () => ({
  useProjectsStore: (selector: (state: { preferences: { language: string } }) => unknown) =>
    selector({ preferences: { language: 'en' } }),
}))

import { ControlPairingConsent } from './ControlPairingConsent'

const requestedAt = 1_700_000_000

function pendingRequest(overrides: Record<string, unknown> = {}) {
  return {
    pending: true,
    client_id: 'transcripts',
    code: 'code-from-the-window-only',
    status: 'pending',
    requested_at: requestedAt,
    expires_at: Math.floor(Date.now() / 1000) + 120,
    expires_in_seconds: 120,
    ...overrides,
  }
}

describe('ControlPairingConsent', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    tauri.requestHandler = null
    tauri.onControlPairingRequested.mockImplementation((handler: () => void) => {
      tauri.requestHandler = handler
      return Promise.resolve(() => {})
    })
    tauri.controlPairingPending.mockResolvedValue({ pending: false })
    tauri.controlPairingDecide.mockReset()
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  it('renders nothing while no client is asking', async () => {
    const { container } = render(<ControlPairingConsent />)
    await waitFor(() => expect(tauri.controlPairingPending).toHaveBeenCalled())
    expect(container.querySelector('[data-control-pairing-consent]')).toBeNull()
  })

  it('shows the client and the code, which only this window can read', async () => {
    tauri.controlPairingPending.mockResolvedValue(pendingRequest())
    render(<ControlPairingConsent />)
    expect(await screen.findByText('Pairing request')).toBeTruthy()
    expect(screen.getByText('transcripts')).toBeTruthy()
    expect(screen.getByText('code-from-the-window-only')).toBeTruthy()
    expect(screen.getByRole('button', { name: /allow/i })).toBeTruthy()
    expect(screen.getByRole('button', { name: /deny/i })).toBeTruthy()
  })

  it('asks the control plane to approve and then stops offering the buttons', async () => {
    tauri.controlPairingPending.mockResolvedValue(pendingRequest())
    tauri.controlPairingDecide.mockResolvedValue({
      client_id: 'transcripts',
      status: 'approved',
      approved: true,
    })
    render(<ControlPairingConsent />)
    fireEvent.click(await screen.findByRole('button', { name: /allow/i }))
    await waitFor(() => expect(tauri.controlPairingDecide).toHaveBeenCalledWith(true))
    expect(await screen.findByText(/waiting for the client/i)).toBeTruthy()
    expect(screen.queryByRole('button', { name: /allow/i })).toBeNull()
  })

  it('denies without ever minting a session', async () => {
    tauri.controlPairingPending.mockResolvedValue(pendingRequest())
    tauri.controlPairingDecide.mockResolvedValue({
      client_id: 'transcripts',
      status: 'denied',
      approved: false,
    })
    render(<ControlPairingConsent />)
    fireEvent.click(await screen.findByRole('button', { name: /deny/i }))
    await waitFor(() => expect(tauri.controlPairingDecide).toHaveBeenCalledWith(false))
    expect(await screen.findByText('Denied.')).toBeTruthy()
  })

  it('surfaces a refused decision instead of pretending it worked', async () => {
    tauri.controlPairingPending.mockResolvedValue(pendingRequest())
    tauri.controlPairingDecide.mockRejectedValue('pairing_expired')
    render(<ControlPairingConsent />)
    fireEvent.click(await screen.findByRole('button', { name: /allow/i }))
    expect(await screen.findByText('pairing_expired')).toBeTruthy()
    expect(screen.getByRole('button', { name: /allow/i })).toBeTruthy()
  })

  it('opens the prompt when the control plane pushes a request', async () => {
    render(<ControlPairingConsent />)
    await waitFor(() => expect(tauri.requestHandler).toBeTypeOf('function'))
    tauri.controlPairingPending.mockResolvedValue(pendingRequest())
    tauri.requestHandler?.()
    expect(await screen.findByText('code-from-the-window-only')).toBeTruthy()
  })
})
