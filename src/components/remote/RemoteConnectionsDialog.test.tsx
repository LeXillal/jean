import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { RemoteConnectionsDialog } from './RemoteConnectionsDialog'

const {
  addRemoteConnection,
  selectConnection,
  fetchRemoteServerInfo,
  probeConnectionServerInfo,
  getLocalJeanVersion,
  warnRemoteVersionMismatch,
  invoke,
  isNativeApp,
  listenLocal,
  updateRemoteConnection,
  useRemoteConnections,
} = vi.hoisted(() => ({
  addRemoteConnection: vi.fn(() => ({ id: 'remote-1' })),
  selectConnection: vi.fn(),
  fetchRemoteServerInfo: vi.fn(async () => ({
    ok: true,
    appVersion: '0.1.69',
    webBuildId: '0.1.69-test',
  })),
  probeConnectionServerInfo: vi.fn(async () => ({
    ok: true,
    appVersion: '0.1.69',
    webBuildId: '0.1.69-test',
  })),
  getLocalJeanVersion: vi.fn(() => '0.1.69'),
  warnRemoteVersionMismatch: vi.fn(() => false),
  invoke: vi.fn(),
  isNativeApp: vi.fn(() => false),
  listenLocal: vi.fn(async () => () => {
    // no-op unsubscribe
  }),
  updateRemoteConnection: vi.fn(async () => ({ id: 'remote-1' })),
  useRemoteConnections: vi.fn(() => [] as unknown[]),
}))

vi.mock('@/lib/remote-connections', () => ({
  LOCAL_CONNECTION_ID: 'local',
  addRemoteConnection,
  getActiveConnectionId: () => 'local',
  removeRemoteConnection: vi.fn(),
  markConnectionSwitch: vi.fn(),
  parseOptionalSshPort: (raw: string) => {
    const trimmed = raw.trim()
    if (!trimmed) return undefined
    const port = Number(trimmed)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error('SSH port must be an integer between 1 and 65535.')
    }
    return port
  },
  parseRemoteConnectionInput: (url: string, token: string) => {
    const parsed = new URL(url)
    const resolvedToken =
      token.trim() || parsed.searchParams.get('token')?.trim() || ''
    parsed.search = ''
    return {
      url: parsed.toString().replace(/\/$/, ''),
      token: resolvedToken,
    }
  },
  selectConnection,
  updateRemoteConnection,
  useRemoteConnections,
}))

vi.mock('@/lib/remote-version', () => ({
  checkRemoteVersionCompatibility: (remote: string | null | undefined) => ({
    compatible: !remote || remote === '0.1.69',
    localVersion: '0.1.69',
    remoteVersion: remote ?? null,
    message: remote
      ? `This Jean app is v0.1.69, but the remote server is v${remote}.`
      : undefined,
  }),
  fetchRemoteServerInfo,
  formatJeanVersionLabel: (version: string | null | undefined) =>
    version ? `v${version.replace(/^v/, '')}` : 'version unknown',
  getLocalJeanVersion,
  warnRemoteVersionMismatch,
}))

vi.mock('@/lib/environment', () => ({
  isNativeApp: () => isNativeApp(),
}))

vi.mock('@/lib/transport', () => ({
  invoke,
  listenLocal,
  probeConnectionServerInfo,
}))

describe('RemoteConnectionsDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    fetchRemoteServerInfo.mockResolvedValue({
      ok: true,
      appVersion: '0.1.69',
      webBuildId: '0.1.69-test',
    })
    probeConnectionServerInfo.mockResolvedValue({
      ok: true,
      appVersion: '0.1.69',
      webBuildId: '0.1.69-test',
    })
    warnRemoteVersionMismatch.mockReturnValue(false)
    isNativeApp.mockReturnValue(false)
    addRemoteConnection.mockReturnValue({ id: 'remote-1' })
    updateRemoteConnection.mockResolvedValue({ id: 'remote-1' })
    useRemoteConnections.mockReturnValue([])
  })

  it('adds and selects a remote from a complete Web Access URL without probing it directly (web proxy)', async () => {
    const reloadApp = vi.fn()
    render(<RemoteConnectionsDialog reloadApp={reloadApp} />)

    fireEvent.click(screen.getByRole('button', { name: 'Jean connections' }))
    fireEvent.click(screen.getByRole('button', { name: 'Add remote' }))
    fireEvent.change(screen.getByLabelText('Name'), {
      target: { value: 'Build server' },
    })
    fireEvent.change(screen.getByLabelText('Web Access URL'), {
      target: { value: 'https://jean.example.com/?token=secret' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save & Connect' }))

    await waitFor(() => {
      expect(addRemoteConnection).toHaveBeenCalledWith({
        name: 'Build server',
        url: 'https://jean.example.com/?token=secret',
        token: '',
        sshUser: undefined,
        sshHost: undefined,
        sshPort: 22,
      })
      expect(selectConnection).toHaveBeenCalledWith('remote-1')
      expect(reloadApp).toHaveBeenCalled()
    })
    // Web clients never hit the remote directly; the browser holds no remote
    // token and there is no id yet to relay through the proxy.
    expect(fetchRemoteServerInfo).not.toHaveBeenCalled()
    expect(probeConnectionServerInfo).not.toHaveBeenCalled()
  })

  it('probes the remote and still connects on mismatch when adding in the native app', async () => {
    isNativeApp.mockReturnValue(true)
    fetchRemoteServerInfo.mockResolvedValueOnce({
      ok: true,
      appVersion: '0.2.0',
      webBuildId: '0.2.0-test',
    })
    warnRemoteVersionMismatch.mockReturnValueOnce(true)

    const reloadApp = vi.fn()
    render(<RemoteConnectionsDialog reloadApp={reloadApp} />)

    fireEvent.click(screen.getByRole('button', { name: 'Jean connections' }))
    expect(screen.getByText('v0.1.69')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Add remote' }))
    // Native add defaults to the SSH install tab; switch to the URL tab.
    fireEvent.click(screen.getByRole('tab', { name: /Existing URL/i }))
    fireEvent.change(screen.getByLabelText('Web Access URL'), {
      target: { value: 'https://jean.example.com/?token=secret' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save & Connect' }))

    await waitFor(() => {
      expect(fetchRemoteServerInfo).toHaveBeenCalledWith(
        'https://jean.example.com',
        'secret'
      )
      expect(warnRemoteVersionMismatch).toHaveBeenCalledWith('0.2.0')
      expect(addRemoteConnection).toHaveBeenCalled()
      expect(selectConnection).toHaveBeenCalledWith('remote-1')
      expect(reloadApp).toHaveBeenCalled()
    })
  })

  it('does not pre-fill the saved token when editing and keeps it blank in the PUT (web)', async () => {
    useRemoteConnections.mockReturnValue([
      {
        id: 'conn-1',
        name: 'ses-temps',
        url: 'https://jean.example.com',
      },
    ])

    render(<RemoteConnectionsDialog reloadApp={vi.fn()} />)

    fireEvent.click(screen.getByRole('button', { name: 'Jean connections' }))
    fireEvent.click(screen.getByRole('button', { name: 'Edit ses-temps' }))

    // The write-only token field must never be pre-filled with a saved token.
    expect(screen.getByLabelText('Access token')).toHaveValue('')

    fireEvent.click(screen.getByRole('button', { name: 'Save' }))

    await waitFor(() => {
      expect(updateRemoteConnection).toHaveBeenCalledWith(
        'conn-1',
        expect.objectContaining({ token: '' })
      )
    })
  })

  it('saves optional SSH fields when adding a remote URL', async () => {
    render(<RemoteConnectionsDialog reloadApp={vi.fn()} />)

    fireEvent.click(screen.getByRole('button', { name: 'Jean connections' }))
    fireEvent.click(screen.getByRole('button', { name: 'Add remote' }))
    fireEvent.change(screen.getByLabelText('Name'), {
      target: { value: 'Build server' },
    })
    fireEvent.change(screen.getByLabelText('Web Access URL'), {
      target: { value: 'https://jean.example.com/?token=secret' },
    })
    fireEvent.change(screen.getByLabelText('SSH user'), {
      target: { value: 'ubuntu' },
    })
    fireEvent.change(screen.getByLabelText('SSH host'), {
      target: { value: '192.168.1.50' },
    })
    fireEvent.change(screen.getByLabelText('SSH port'), {
      target: { value: '2222' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save & Connect' }))

    await waitFor(() => {
      expect(addRemoteConnection).toHaveBeenCalledWith({
        name: 'Build server',
        url: 'https://jean.example.com/?token=secret',
        token: '',
        sshUser: 'ubuntu',
        sshHost: '192.168.1.50',
        sshPort: 2222,
      })
    })
  })

  it('installs jean-server via SSH user and host in the native app', async () => {
    isNativeApp.mockReturnValue(true)
    invoke.mockResolvedValue({
      name: 'build-box',
      url: 'http://192.168.1.50:3456',
      token: 'tok-abc',
      alreadyInstalled: false,
      installMode: 'system',
      ready: true,
      log: 'ok',
    })
    const reloadApp = vi.fn()

    render(<RemoteConnectionsDialog reloadApp={reloadApp} />)

    fireEvent.click(screen.getByRole('button', { name: 'Jean connections' }))
    fireEvent.click(screen.getByRole('button', { name: 'Add remote' }))

    expect(
      screen.getByRole('tab', { name: /Install via SSH/i })
    ).toBeInTheDocument()
    expect(
      screen.getByRole('tab', { name: /Existing URL/i })
    ).toBeInTheDocument()

    fireEvent.change(screen.getByLabelText('Name'), {
      target: { value: 'build-box' },
    })
    fireEvent.change(screen.getByLabelText('SSH user'), {
      target: { value: 'ubuntu' },
    })
    fireEvent.change(screen.getByLabelText('Host / IP'), {
      target: { value: '192.168.1.50' },
    })
    fireEvent.click(screen.getByRole('button', { name: /Install & Connect/i }))

    await waitFor(() => {
      expect(invoke).toHaveBeenCalledWith('install_remote_jean_server', {
        name: 'build-box',
        user: 'ubuntu',
        host: '192.168.1.50',
        sshPort: 22,
        jeanPort: 3456,
        userInstall: null,
      })
    })

    await waitFor(() => {
      expect(addRemoteConnection).toHaveBeenCalledWith({
        name: 'build-box',
        url: 'http://192.168.1.50:3456',
        token: 'tok-abc',
        sshUser: 'ubuntu',
        sshHost: '192.168.1.50',
        sshPort: 22,
      })
      expect(selectConnection).toHaveBeenCalledWith('remote-1')
      expect(reloadApp).toHaveBeenCalled()
    })
  })

  it('can switch from install mode to existing URL mode', () => {
    isNativeApp.mockReturnValue(true)
    render(<RemoteConnectionsDialog reloadApp={vi.fn()} />)

    fireEvent.click(screen.getByRole('button', { name: 'Jean connections' }))
    fireEvent.click(screen.getByRole('button', { name: 'Add remote' }))
    fireEvent.click(screen.getByRole('tab', { name: /Existing URL/i }))

    expect(screen.getByLabelText('Web Access URL')).toBeInTheDocument()
    expect(
      screen.getByRole('button', { name: 'Save & Connect' })
    ).toBeInTheDocument()
  })
})
