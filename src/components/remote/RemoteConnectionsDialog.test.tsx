import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { RemoteConnectionsDialog } from './RemoteConnectionsDialog'

const {
  addRemoteConnection,
  selectConnection,
  fetchRemoteServerInfo,
  getLocalJeanVersion,
  warnRemoteVersionMismatch,
  invoke,
  isNativeApp,
  listenLocal,
  useRemoteConnections,
} = vi.hoisted(() => ({
  addRemoteConnection: vi.fn(() => ({ id: 'remote-1' })),
  selectConnection: vi.fn(),
  fetchRemoteServerInfo: vi.fn(async () => ({
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
  useRemoteConnections: vi.fn((): unknown[] => []),
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
  updateRemoteConnection: vi.fn(),
  useRemoteConnections: () => useRemoteConnections(),
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
  isInvalidTokenError: (error: unknown) =>
    String(error instanceof Error ? error.message : error).startsWith(
      'Invalid access token'
    ),
  warnRemoteVersionMismatch,
}))

vi.mock('@/lib/environment', () => ({
  isNativeApp: () => isNativeApp(),
}))

vi.mock('@/lib/transport', () => ({
  invoke,
  listenLocal,
}))

describe('RemoteConnectionsDialog', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    fetchRemoteServerInfo.mockResolvedValue({
      ok: true,
      appVersion: '0.1.69',
      webBuildId: '0.1.69-test',
    })
    warnRemoteVersionMismatch.mockReturnValue(false)
    isNativeApp.mockReturnValue(false)
    useRemoteConnections.mockReturnValue([])
  })

  it('adds and selects a remote from a complete Web Access URL', async () => {
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
      expect(fetchRemoteServerInfo).toHaveBeenCalledWith(
        'https://jean.example.com',
        'secret'
      )
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
  })

  it('shows local version and still connects when remote mismatches', async () => {
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
    fireEvent.change(screen.getByLabelText('Web Access URL'), {
      target: { value: 'https://jean.example.com/?token=secret' },
    })
    fireEvent.click(screen.getByRole('button', { name: 'Save & Connect' }))

    await waitFor(() => {
      expect(warnRemoteVersionMismatch).toHaveBeenCalledWith('0.2.0')
      expect(addRemoteConnection).toHaveBeenCalled()
      expect(selectConnection).toHaveBeenCalledWith('remote-1')
      expect(reloadApp).toHaveBeenCalled()
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

  describe('connection status dot', () => {
    const remote = {
      id: 'remote-1',
      name: 'Build server',
      url: 'https://jean.example.com',
      token: 'secret',
    }

    const openDialog = () => {
      render(<RemoteConnectionsDialog reloadApp={vi.fn()} />)
      fireEvent.click(screen.getByRole('button', { name: 'Jean connections' }))
    }

    it('reports a reachable remote as reachable, not merely selected', async () => {
      useRemoteConnections.mockReturnValue([remote])
      openDialog()

      // 'local' is the active connection here, so a green dot on the remote can
      // only mean the probe answered.
      await waitFor(() => {
        expect(screen.getByRole('img', { name: 'Reachable' })).toHaveClass(
          'bg-emerald-500'
        )
      })
    })

    it('distinguishes an unreachable remote from a rejected token', async () => {
      useRemoteConnections.mockReturnValue([remote])
      fetchRemoteServerInfo.mockRejectedValue(
        new Error('Timed out reaching the Jean server.')
      )
      openDialog()

      await waitFor(() => {
        expect(screen.getByRole('img', { name: 'Unreachable' })).toHaveClass(
          'bg-muted-foreground/35'
        )
      })
      expect(screen.getByText('unreachable')).toBeInTheDocument()
    })

    it('flags a rejected token as an auth failure', async () => {
      useRemoteConnections.mockReturnValue([remote])
      fetchRemoteServerInfo.mockRejectedValue(
        new Error('Invalid access token for this Jean server.')
      )
      openDialog()

      await waitFor(() => {
        expect(
          screen.getByRole('img', { name: 'Authentication failed' })
        ).toHaveClass('bg-destructive')
      })
      // The old label sent the user debugging the network for a token problem.
      expect(screen.getByText('auth failed')).toBeInTheDocument()
      expect(screen.queryByText('unreachable')).not.toBeInTheDocument()
    })

    it('shows Local as reachable without probing it', () => {
      openDialog()

      expect(screen.getByRole('img', { name: 'Reachable' })).toBeInTheDocument()
      expect(fetchRemoteServerInfo).not.toHaveBeenCalled()
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
