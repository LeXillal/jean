import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { FALLBACK_APP_VERSION } from './app-version'

const setWsConnectedMock = vi.fn()

class MockWebSocket {
  static CONNECTING = 0
  static OPEN = 1
  static CLOSING = 2
  static CLOSED = 3
  static instances: MockWebSocket[] = []

  readyState = MockWebSocket.CONNECTING
  onopen: ((event: Event) => void) | null = null
  onmessage: ((event: MessageEvent) => void) | null = null
  onclose: ((event: Event) => void) | null = null
  onerror: ((event: Event) => void) | null = null
  send = vi.fn()
  close = vi.fn(() => {
    this.readyState = MockWebSocket.CLOSED
    this.onclose?.(new Event('close'))
  })

  constructor(public url: string) {
    MockWebSocket.instances.push(this)
    queueMicrotask(() => {
      this.readyState = MockWebSocket.OPEN
      this.onopen?.(new Event('open'))
    })
  }

  receive(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) } as MessageEvent)
  }
}

async function flushAsync() {
  await Promise.resolve()
  await Promise.resolve()
  await Promise.resolve()
  await Promise.resolve()
}

function getWs(index: number): MockWebSocket {
  const ws = MockWebSocket.instances[index]
  if (!ws) throw new Error(`Expected websocket instance ${index}`)
  return ws
}

async function loadTransportModule() {
  vi.resetModules()
  vi.doMock('./environment', () => ({
    isNativeApp: () => false,
    isNativeOpenAllowed: () => false,
    setWsConnected: setWsConnectedMock,
    setWebAccessEnabled: vi.fn(),
  }))
  return import('./transport')
}

async function loadNativeTransportModule(
  tauriInvoke: ReturnType<typeof vi.fn>
) {
  vi.resetModules()
  vi.doMock('./environment', () => ({
    isNativeApp: () => true,
    isNativeOpenAllowed: () => false,
    setWsConnected: setWsConnectedMock,
    setWebAccessEnabled: vi.fn(),
  }))
  vi.doMock('@tauri-apps/api/core', () => ({ invoke: tauriInvoke }))
  return import('./transport')
}

/**
 * Mock the connection registry for a single selected instance. The transport
 * resolves focus through `getActiveConnectionId()`, so the mock must keep the
 * id, the list and the active connection consistent with each other.
 */
function mockRemoteConnections(
  remote: { id: string; name: string; url: string; token?: string } | null
) {
  vi.doMock('./remote-connections', () => ({
    LOCAL_CONNECTION_ID: 'local',
    getActiveConnectionId: () => remote?.id ?? 'local',
    getActiveRemoteConnection: () => remote,
    getRemoteConnections: () => (remote ? [remote] : []),
  }))
}

async function loadRemoteNativeTransportModule(
  remote?: {
    id: string
    name: string
    url: string
    token: string
    sshUser?: string
    sshHost?: string
    sshPort?: number
  },
  tauriInvoke?: ReturnType<typeof vi.fn>,
  options?: { nativeOpenAllowed?: boolean }
) {
  vi.resetModules()
  const nativeOpenAllowed = options?.nativeOpenAllowed ?? false
  vi.doMock('./environment', () => ({
    isNativeApp: () => true,
    isNativeOpenAllowed: () => nativeOpenAllowed,
    setWsConnected: setWsConnectedMock,
    setWebAccessEnabled: vi.fn(),
  }))
  mockRemoteConnections(
    remote ?? {
      id: 'remote-1',
      name: 'Server',
      url: 'https://jean.example.com',
      token: 'secret',
    }
  )
  if (tauriInvoke) {
    vi.doMock('@tauri-apps/api/core', () => ({ invoke: tauriInvoke }))
  }
  return import('./transport')
}

async function loadRemoteWebTransportModule(remote: {
  id: string
  name: string
  url: string
  token?: string
}) {
  vi.resetModules()
  vi.doMock('./environment', () => ({
    isNativeApp: () => false,
    isNativeOpenAllowed: () => false,
    setWsConnected: setWsConnectedMock,
    setWebAccessEnabled: vi.fn(),
  }))
  mockRemoteConnections(remote)
  return import('./transport')
}

describe('transport bootstrap', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    MockWebSocket.instances = []
    localStorage.clear()
    vi.stubGlobal('WebSocket', MockWebSocket)
    // Auth responses include the local package version so native remote
    // version checks pass unless a test intentionally mismatches.
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          ok: true,
          appVersion: FALLBACK_APP_VERSION,
        }),
      })
    )
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    vi.doUnmock('./environment')
    vi.doUnmock('@tauri-apps/api/core')
    vi.doUnmock('@tauri-apps/api/event')
    vi.doUnmock('./remote-connections')
    // Restore the inert localStorage default so a hub-token test cannot leak
    // its value into later tests.
    vi.mocked(localStorage.getItem).mockReturnValue(null)
  })

  it('routes native shared commands to the selected remote Jean', async () => {
    const transport = await loadRemoteNativeTransportModule()

    transport.connectTransport()
    await waitFor(() => expect(MockWebSocket.instances.length).toBe(1))
    await flushAsync()
    const ws = getWs(0)
    expect(ws.url).toBe('wss://jean.example.com/ws?token=secret')

    const request = transport.invoke('list_projects')
    await waitFor(() =>
      expect(ws.send).toHaveBeenCalledWith(
        expect.stringContaining('"command":"list_projects"')
      )
    )

    expect(fetch).toHaveBeenCalledWith(
      'https://jean.example.com/api/auth?token=secret',
      expect.objectContaining({ signal: expect.anything() })
    )
    const sent = JSON.parse(String(ws.send.mock.calls.at(-1)?.[0]))
    ws.receive({ type: 'response', id: sent.id, data: [] })
    await request
  })

  it('relays web remote traffic through the origin hub proxy with the hub token only', async () => {
    vi.mocked(localStorage.getItem).mockImplementation(key =>
      key === 'jean-http-token' ? 'hubtoken' : null
    )
    const transport = await loadRemoteWebTransportModule({
      id: 'remote-1',
      name: 'Server',
      // Direct URL and remote token must never reach the browser transport.
      url: 'https://direct.example.com',
      token: 'remoteToken',
    })

    transport.connectTransport()
    await waitFor(() => expect(MockWebSocket.instances.length).toBe(1))
    await flushAsync()
    const ws = getWs(0)

    const origin = window.location.origin
    const wsHost = origin.replace(/^http/, 'ws')
    expect(ws.url).toBe(`${wsHost}/remote/remote-1/ws?token=hubtoken`)
    expect(ws.url).not.toContain('remoteToken')
    expect(ws.url).not.toContain('direct.example.com')

    expect(fetch).toHaveBeenCalledWith(
      `${origin}/remote/remote-1/api/auth?token=hubtoken`,
      expect.objectContaining({ signal: expect.anything() })
    )
    const authCall = vi
      .mocked(fetch)
      .mock.calls.find(call => String(call[0]).includes('/api/auth'))
    expect(String(authCall?.[0])).not.toContain('remoteToken')
  })

  it('keeps native menu listeners on the local shell for remote connections', async () => {
    const tauriListen = vi.fn().mockResolvedValue(() => {
      /* noop cleanup */
    })
    vi.doMock('@tauri-apps/api/event', () => ({ listen: tauriListen }))
    const transport = await loadRemoteNativeTransportModule()
    const handler = vi.fn()

    await transport.listenLocal('menu-quick-menu', handler)

    expect(tauriListen).toHaveBeenCalledWith('menu-quick-menu', handler)
    expect(MockWebSocket.instances).toHaveLength(0)
  })

  it('makes native listener cleanup idempotent and contains teardown errors', async () => {
    const cleanup = vi
      .fn()
      .mockRejectedValue(new Error('listener already gone'))
    const tauriListen = vi.fn().mockResolvedValue(cleanup)
    vi.doMock('@tauri-apps/api/event', () => ({ listen: tauriListen }))
    const transport = await loadNativeTransportModule(vi.fn())

    const unlisten = await transport.listen('chat:chunk', vi.fn())

    expect(unlisten()).toBeUndefined()
    expect(unlisten()).toBeUndefined()
    await flushAsync()
    expect(cleanup).toHaveBeenCalledTimes(1)
  })

  it('explains how to troubleshoot a reachable remote rejected by the desktop client', async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new TypeError('Load failed'))
    const transport = await loadRemoteNativeTransportModule()
    const { result } = renderHook(() => transport.useWsAuthError())

    transport.connectTransport()

    await waitFor(() =>
      expect(result.current).toBe(
        "Jean could not reach the server's authentication endpoint. Check that the server is running and the URL and port are correct. If the address opens in a browser, update and restart the remote Jean server so it allows desktop connections (CORS)."
      )
    )
    expect(result.current).not.toContain('secret')
  })

  it('still connects native remotes when appVersion mismatches', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ ok: true, appVersion: '9.9.9' }),
    } as Response)

    const transport = await loadRemoteNativeTransportModule()
    const { result } = renderHook(() => transport.useWsAuthError())

    transport.connectTransport()

    // Mismatch only warns; auth error stays null and the socket still opens.
    await waitFor(() => expect(MockWebSocket.instances.length).toBe(1))
    expect(result.current).toBeNull()
  })

  it('routes shared native commands through the jean-core dispatcher', async () => {
    const tauriInvoke = vi.fn().mockResolvedValue([{ id: 'project-1' }])
    const transport = await loadNativeTransportModule(tauriInvoke)

    await transport.invoke('list_projects')

    expect(tauriInvoke).toHaveBeenCalledWith('dispatch_core_command', {
      command: 'list_projects',
      args: {},
    })
  })

  it('keeps desktop-only commands on their native Tauri handlers', async () => {
    const tauriInvoke = vi.fn().mockResolvedValue(undefined)
    const transport = await loadNativeTransportModule(tauriInvoke)

    await transport.invoke('set_window_vibrancy', { enabled: true })

    expect(tauriInvoke).toHaveBeenCalledWith('set_window_vibrancy', {
      enabled: true,
    })
  })

  it('opens remote worktrees in local Zed via ssh:// targets', async () => {
    const tauriInvoke = vi.fn().mockResolvedValue(undefined)
    const transport = await loadRemoteNativeTransportModule(
      {
        id: 'remote-1',
        name: 'Server',
        url: 'https://jean.example.com',
        token: 'secret',
        sshUser: 'ubuntu',
        sshHost: '192.168.1.50',
      },
      tauriInvoke
    )

    await transport.invoke('open_worktree_in_editor', {
      worktreePath: '/home/ubuntu/jean/app/feature',
      editor: 'zed',
    })

    expect(tauriInvoke).toHaveBeenCalledWith('open_worktree_in_editor', {
      worktreePath: 'ssh://ubuntu@192.168.1.50/home/ubuntu/jean/app/feature',
      editor: 'zed',
    })
  })

  it('prefers backend native-open over ssh:// remap when the remote allows it', async () => {
    // WSL/--allow-native-open headless: editor must go through WebSocket
    // dispatch (same as Finder/Terminal), not local Windows-side ssh://.
    const tauriInvoke = vi.fn().mockResolvedValue(undefined)
    const transport = await loadRemoteNativeTransportModule(
      {
        id: 'remote-1',
        name: 'WSL Jean',
        url: 'http://127.0.0.1:3456',
        token: 'secret',
      },
      tauriInvoke,
      { nativeOpenAllowed: true }
    )

    transport.connectTransport()
    await waitFor(() => expect(MockWebSocket.instances.length).toBe(1))
    await flushAsync()
    const ws = getWs(0)

    const request = transport.invoke('open_worktree_in_editor', {
      worktreePath: '/home/ubuntu/jean/app/feature',
      editor: 'zed',
    })
    await waitFor(() =>
      expect(ws.send).toHaveBeenCalledWith(
        expect.stringContaining('"command":"open_worktree_in_editor"')
      )
    )
    // Resolve the pending WS invoke so it does not leak.
    const sent = JSON.parse(String(ws.send.mock.calls.at(-1)?.[0]))
    ws.receive({ type: 'response', id: sent.id, data: null })
    await request

    expect(tauriInvoke).not.toHaveBeenCalled()
  })

  it('rejects non-Zed remote editor opens with a clear error', async () => {
    const tauriInvoke = vi.fn().mockResolvedValue(undefined)
    const transport = await loadRemoteNativeTransportModule(
      {
        id: 'remote-1',
        name: 'Server',
        url: 'https://jean.example.com',
        token: 'secret',
        sshUser: 'ubuntu',
        sshHost: '192.168.1.50',
      },
      tauriInvoke
    )

    await expect(
      transport.invoke('open_worktree_in_editor', {
        worktreePath: '/tmp',
        editor: 'vscode',
      })
    ).rejects.toThrow(/Zed/)
    expect(tauriInvoke).not.toHaveBeenCalled()
  })

  it('trades a hub token in the URL for a cookie instead of persisting it', async () => {
    const reload = vi.fn()
    vi.stubGlobal('location', {
      href: 'https://jean.example.com/?token=hub-secret',
      search: '?token=hub-secret',
      origin: 'https://jean.example.com',
      reload,
    })
    const replaceState = vi
      .spyOn(window.history, 'replaceState')
      .mockImplementation(() => undefined)
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: true, json: async () => ({}) })
    vi.stubGlobal('fetch', fetchMock)

    const transport = await loadTransportModule()
    transport.connectTransport()
    await flushAsync()

    // The hub token is exchanged for an HttpOnly cookie via /api/login…
    expect(fetchMock).toHaveBeenCalledWith(
      'https://jean.example.com/api/login',
      expect.objectContaining({ method: 'POST', credentials: 'same-origin' })
    )
    expect(JSON.parse(String(fetchMock.mock.calls[0]?.[1]?.body))).toEqual({
      token: 'hub-secret',
    })

    // …never left in localStorage (XSS-readable) and never opened as a
    // token-bearing WebSocket. The reload re-authenticates from the cookie.
    expect(localStorage.getItem('jean-http-token')).toBeNull()
    expect(MockWebSocket.instances).toHaveLength(0)
    expect(reload).toHaveBeenCalled()

    replaceState.mockRestore()
  })

  it('does not open websocket until bootstrap explicitly connects it', async () => {
    const transport = await loadTransportModule()

    await transport.listen('chat:chunk', vi.fn())
    expect(MockWebSocket.instances).toHaveLength(0)

    transport.connectTransport()
    await flushAsync()

    expect(fetch).toHaveBeenCalledTimes(1)
    expect(MockWebSocket.instances).toHaveLength(1)
    expect(setWsConnectedMock).toHaveBeenCalledWith(true)
  })

  it('retries while establishing the initial connection', async () => {
    const fetchMock = vi.mocked(fetch)
    fetchMock
      .mockRejectedValueOnce(new Error('server starting'))
      .mockResolvedValueOnce({ ok: true } as Response)
    const transport = await loadTransportModule()

    transport.connectTransport()
    await flushAsync()
    expect(MockWebSocket.instances).toHaveLength(0)

    await new Promise(resolve => setTimeout(resolve, 150))
    await flushAsync()

    expect(MockWebSocket.instances).toHaveLength(1)
    expect(setWsConnectedMock).toHaveBeenCalledWith(true)
  })

  it('buffers bootstrap replay events before listeners connect and replays them in seq order', async () => {
    const transport = await loadTransportModule()
    const handler = vi.fn()

    transport.ingestBootstrapEvents([
      {
        type: 'event',
        event: 'chat:chunk',
        payload: { session_id: 'session-1', content: 'second' },
        seq: 2,
      },
      {
        type: 'event',
        event: 'chat:chunk',
        payload: { session_id: 'session-1', content: 'first' },
        seq: 1,
      },
    ])

    await transport.listen('chat:chunk', handler)

    expect(handler.mock.calls).toEqual([
      [{ payload: { session_id: 'session-1', content: 'first' } }],
      [{ payload: { session_id: 'session-1', content: 'second' } }],
    ])
    expect(MockWebSocket.instances).toHaveLength(0)
  })

  it('dedupes terminal replay events by terminal sequence number', async () => {
    const transport = await loadTransportModule()
    const handler = vi.fn()

    await transport.listen('terminal:output', handler)
    transport.connectTransport()
    await flushAsync()

    const ws = getWs(0)
    ws.receive({
      type: 'event',
      event: 'terminal:output',
      payload: { terminal_id: 'term-1', data: 'first' },
      seq: 10,
    })
    ws.receive({
      type: 'event',
      event: 'terminal:output',
      payload: { terminal_id: 'term-1', data: 'duplicate' },
      seq: 10,
    })
    ws.receive({
      type: 'event',
      event: 'terminal:output',
      payload: { terminal_id: 'term-1', data: 'second' },
      seq: 11,
    })

    expect(handler.mock.calls).toEqual([
      [{ payload: { terminal_id: 'term-1', data: 'first' } }],
      [{ payload: { terminal_id: 'term-1', data: 'second' } }],
    ])
  })

  it('ignores app-level heartbeat messages without dispatching events', async () => {
    const transport = await loadTransportModule()
    const handler = vi.fn()

    await transport.listen('heartbeat', handler)
    transport.connectTransport()
    await flushAsync()

    getWs(0).receive({ type: 'heartbeat' })

    expect(handler).not.toHaveBeenCalled()
  })

  it('keeps idle websocket alive when app-level heartbeats arrive', async () => {
    vi.useFakeTimers()
    const transport = await loadTransportModule()

    transport.connectTransport()
    await flushAsync()

    const ws = getWs(0)
    vi.advanceTimersByTime(49_000)
    expect(ws.close).not.toHaveBeenCalled()

    ws.receive({ type: 'heartbeat' })
    vi.advanceTimersByTime(40_000)
    expect(ws.close).not.toHaveBeenCalled()

    vi.advanceTimersByTime(11_000)
    expect(ws.close).toHaveBeenCalledTimes(1)

    vi.useRealTimers()
  })

  it('replaces a stale websocket immediately when the page returns', async () => {
    vi.useFakeTimers()
    Object.defineProperty(document, 'hidden', {
      configurable: true,
      value: false,
    })
    const transport = await loadTransportModule()

    transport.connectTransport()
    await flushAsync()
    const ws = getWs(0)

    vi.advanceTimersByTime(51_000)
    document.dispatchEvent(new Event('visibilitychange'))

    expect(ws.close).toHaveBeenCalledTimes(1)
  })

  it('uses extended timeout for terminal lifecycle commands', async () => {
    vi.useFakeTimers()
    const transport = await loadTransportModule()

    let rejected = false
    const request = transport
      .invoke('terminal_write', { terminalId: 'term-1', data: 'echo hi\r' })
      .catch(() => {
        rejected = true
      })

    vi.advanceTimersByTime(60_001)
    await flushAsync()

    expect(rejected).toBe(false)

    vi.advanceTimersByTime(30 * 60_000)
    await request

    expect(rejected).toBe(true)

    vi.useRealTimers()
  })

  it('can explicitly request terminal replay from seq zero after full page reload', async () => {
    const transport = await loadTransportModule()

    transport.connectTransport()
    await flushAsync()

    const ws = getWs(0)
    transport.requestTerminalReplay('term-restored', 0)

    expect(ws.send).toHaveBeenCalledWith(
      JSON.stringify({
        type: 'terminal_replay',
        terminal_id: 'term-restored',
        last_seq: 0,
      })
    )
  })

  it('uses highest known sequence for explicit terminal replay requests', async () => {
    const transport = await loadTransportModule()

    transport.connectTransport()
    await flushAsync()

    const ws = getWs(0)
    ws.receive({
      type: 'event',
      event: 'terminal:output',
      payload: { terminal_id: 'term-1', data: 'running' },
      seq: 21,
    })

    transport.requestTerminalReplay('term-1', 0)

    expect(ws.send).toHaveBeenCalledWith(
      JSON.stringify({
        type: 'terminal_replay',
        terminal_id: 'term-1',
        last_seq: 21,
      })
    )
  })

  it('does not open a second socket after an established connection closes', async () => {
    const transport = await loadTransportModule()

    transport.connectTransport()
    await flushAsync()

    const firstWs = getWs(0)
    firstWs.close()
    await new Promise(resolve => setTimeout(resolve, 150))
    await flushAsync()

    expect(MockWebSocket.instances).toHaveLength(1)
  })

  it('notifies established disconnect listeners synchronously', async () => {
    const transport = await loadTransportModule()
    const onDisconnect = vi.fn()

    transport.onEstablishedWsDisconnect(onDisconnect)
    transport.connectTransport()
    await flushAsync()

    getWs(0).close()

    expect(onDisconnect).toHaveBeenCalledOnce()
  })
})

// ---------------------------------------------------------------------------
// Multi-instance transport registry
// ---------------------------------------------------------------------------

const SAT_A = { id: 'sat-a', name: 'Server A', url: 'https://a.example.com' }
const SAT_B = { id: 'sat-b', name: 'Server B', url: 'https://b.example.com' }

/**
 * Load the transport with several registered instances and a MUTABLE focused
 * id, so a test can switch focus the way `selectConnection()` does at runtime.
 */
async function loadMultiInstanceTransportModule(initialActiveId = 'local') {
  vi.resetModules()
  const focus = { id: initialActiveId }
  const connections = [SAT_A, SAT_B]
  vi.doMock('./environment', () => ({
    isNativeApp: () => false,
    isNativeOpenAllowed: () => false,
    setWsConnected: setWsConnectedMock,
    setWebAccessEnabled: vi.fn(),
  }))
  vi.doMock('./remote-connections', () => ({
    LOCAL_CONNECTION_ID: 'local',
    getActiveConnectionId: () => focus.id,
    getActiveRemoteConnection: () =>
      connections.find(item => item.id === focus.id) ?? null,
    getRemoteConnections: () => connections,
  }))
  const transport = await import('./transport')
  return { transport, focus }
}

describe('transport registry (multi-instance)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    MockWebSocket.instances = []
    localStorage.clear()
    vi.stubGlobal('WebSocket', MockWebSocket)
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ appVersion: FALLBACK_APP_VERSION }),
      })
    )
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.resetModules()
  })

  it('returns one stable transport per instance id', async () => {
    const { transport } = await loadMultiInstanceTransportModule()

    const first = transport.getTransport(SAT_A.id)

    expect(transport.getTransport(SAT_A.id)).toBe(first)
    expect(transport.getTransport(SAT_B.id)).not.toBe(first)
  })

  it('opens a satellite socket through the hub proxy for that instance', async () => {
    const { transport } = await loadMultiInstanceTransportModule()

    transport.ensureSatelliteTransport(SAT_A.id)
    await flushAsync()

    expect(getWs(0).url).toContain(`/remote/${SAT_A.id}/ws`)
  })

  it('routes invokeOn to the addressed instance, not the focused one', async () => {
    const { transport } = await loadMultiInstanceTransportModule()

    transport.connectTransport()
    transport.ensureSatelliteTransport(SAT_A.id)
    await flushAsync()

    const hubWs = MockWebSocket.instances.find(
      ws => !ws.url.includes('/remote/')
    )
    const satelliteWs = MockWebSocket.instances.find(ws =>
      ws.url.includes(`/remote/${SAT_A.id}/ws`)
    )
    expect(hubWs).toBeDefined()
    expect(satelliteWs).toBeDefined()

    void transport.invokeOn(SAT_A.id, 'list_all_sessions')
    await flushAsync()

    expect(satelliteWs?.send).toHaveBeenCalledOnce()
    expect(hubWs?.send).not.toHaveBeenCalled()
    expect(String(satelliteWs?.send.mock.calls[0]?.[0])).toContain(
      'list_all_sessions'
    )
  })

  it('tags satellite events with the instance they came from', async () => {
    const { transport } = await loadMultiInstanceTransportModule()
    const handler = vi.fn()

    transport.ensureSatelliteTransport(SAT_A.id)
    await flushAsync()
    await transport.listenOn(SAT_A.id, 'session:updated', handler)

    getWs(0).receive({
      type: 'event',
      event: 'session:updated',
      payload: { session_id: 's1' },
    })

    expect(handler).toHaveBeenCalledWith({
      payload: { session_id: 's1' },
      instanceId: SAT_A.id,
    })
  })

  it('reconnects a satellite in place after its socket drops', async () => {
    const { transport } = await loadMultiInstanceTransportModule()

    transport.ensureSatelliteTransport(SAT_A.id)
    await flushAsync()
    expect(MockWebSocket.instances).toHaveLength(1)

    getWs(0).close()
    await new Promise(resolve => setTimeout(resolve, 250))
    await flushAsync()

    // The focused transport would have stopped at one socket and waited for a
    // page reload; a satellite must come back on its own.
    expect(MockWebSocket.instances.length).toBeGreaterThan(1)
    expect(getWs(1).url).toContain(`/remote/${SAT_A.id}/ws`)
  })

  it('never lets a satellite drop touch global connection state', async () => {
    const { transport } = await loadMultiInstanceTransportModule()
    const onDisconnect = vi.fn()

    transport.onEstablishedWsDisconnect(onDisconnect)
    transport.ensureSatelliteTransport(SAT_A.id)
    await flushAsync()
    setWsConnectedMock.mockClear()

    getWs(0).close()
    await flushAsync()

    expect(onDisconnect).not.toHaveBeenCalled()
    expect(setWsConnectedMock).not.toHaveBeenCalled()
  })

  it('reports per-instance status for the indicator', async () => {
    const { transport } = await loadMultiInstanceTransportModule()

    expect(transport.getInstanceStatus(SAT_A.id)).toBe('idle')

    transport.ensureSatelliteTransport(SAT_A.id)
    await flushAsync()
    expect(transport.getInstanceStatus(SAT_A.id)).toBe('connected')

    getWs(0).close()
    expect(transport.getInstanceStatus(SAT_A.id)).toBe('offline')
  })

  it('re-points bare invoke() at the newly focused instance', async () => {
    const { transport, focus } = await loadMultiInstanceTransportModule(
      SAT_A.id
    )

    transport.connectTransport()
    await flushAsync()
    const wsA = getWs(0)
    expect(wsA.url).toContain(`/remote/${SAT_A.id}/ws`)

    // Switching focus is what `selectConnection()` does; no reload involved.
    focus.id = SAT_B.id
    transport.connectTransport()
    await flushAsync()

    const wsB = MockWebSocket.instances.find(ws =>
      ws.url.includes(`/remote/${SAT_B.id}/ws`)
    )
    expect(wsB).toBeDefined()

    void transport.invoke('list_projects')
    await flushAsync()

    expect(wsB?.send).toHaveBeenCalledOnce()
    expect(wsA.send).not.toHaveBeenCalled()
  })

  it('closes and forgets a released instance', async () => {
    const { transport } = await loadMultiInstanceTransportModule()

    transport.ensureSatelliteTransport(SAT_A.id)
    await flushAsync()
    const ws = getWs(0)
    expect(transport.getLiveTransportIds()).toContain(SAT_A.id)

    transport.releaseTransport(SAT_A.id)

    expect(ws.close).toHaveBeenCalled()
    expect(transport.getLiveTransportIds()).not.toContain(SAT_A.id)
    expect(transport.getInstanceStatus(SAT_A.id)).toBe('idle')
  })
})

describe('transport registry — failure handling', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    MockWebSocket.instances = []
    localStorage.clear()
    vi.stubGlobal('WebSocket', MockWebSocket)
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
    vi.resetModules()
  })

  it('keeps retrying a satellite whose server is simply down', async () => {
    // The hub answers 502 for a remote it cannot reach. That is an outage, not
    // a credential problem: treating it as an auth error would set _authError
    // and permanently disarm the retry loop.
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue({ ok: false, status: 502, json: async () => ({}) })
    )
    const { transport } = await loadMultiInstanceTransportModule()

    transport.ensureSatelliteTransport(SAT_A.id)
    await flushAsync()

    expect(transport.getInstanceStatus(SAT_A.id)).not.toBe('auth-error')

    await new Promise(resolve => setTimeout(resolve, 250))
    await flushAsync()
    expect(vi.mocked(fetch).mock.calls.length).toBeGreaterThan(1)
  })

  it('stops a satellite whose token the hub refuses', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValue({ ok: false, status: 401, json: async () => ({}) })
    )
    const { transport } = await loadMultiInstanceTransportModule()

    transport.ensureSatelliteTransport(SAT_A.id)
    await flushAsync()

    expect(transport.getInstanceStatus(SAT_A.id)).toBe('auth-error')
    const callsAfterFirst = vi.mocked(fetch).mock.calls.length
    await new Promise(resolve => setTimeout(resolve, 250))
    expect(vi.mocked(fetch).mock.calls.length).toBe(callsAfterFirst)
  })

  it('does not reset the backoff for a socket that closes immediately', async () => {
    // The hub accepts the WebSocket upgrade before it knows the remote is
    // reachable, so a dead remote yields open-then-close. If that counted as a
    // successful connection the delay would stay at 100ms and hammer the hub.
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) })
    )
    vi.useFakeTimers()
    const { transport } = await loadMultiInstanceTransportModule()

    transport.ensureSatelliteTransport(SAT_A.id)
    await vi.advanceTimersByTimeAsync(1)
    expect(MockWebSocket.instances).toHaveLength(1)

    // First drop: retried after the initial 100ms.
    getWs(0).close()
    await vi.advanceTimersByTimeAsync(150)
    expect(MockWebSocket.instances).toHaveLength(2)

    // Second drop: the backoff must have grown past 100ms.
    getWs(1).close()
    await vi.advanceTimersByTimeAsync(150)
    expect(MockWebSocket.instances).toHaveLength(2)

    await vi.advanceTimersByTimeAsync(500)
    expect(MockWebSocket.instances).toHaveLength(3)
  })

  it('never opens a socket for an instance released mid-probe', async () => {
    let resolveAuth: ((value: unknown) => void) | undefined
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(
        () =>
          new Promise(resolve => {
            resolveAuth = resolve
          })
      )
    )
    const { transport } = await loadMultiInstanceTransportModule()

    transport.ensureSatelliteTransport(SAT_A.id)
    await flushAsync()
    expect(MockWebSocket.instances).toHaveLength(0)

    // The connection is deleted while the auth probe is still in flight.
    transport.releaseTransport(SAT_A.id)
    resolveAuth?.({ ok: true, json: async () => ({}) })
    await flushAsync()

    // A socket opened now could never be closed — and would resolve to the hub
    // rather than to the removed remote.
    expect(MockWebSocket.instances).toHaveLength(0)
  })

  it('drops satellite events nobody listens for instead of buffering them', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) })
    )
    const { transport } = await loadMultiInstanceTransportModule()

    transport.ensureSatelliteTransport(SAT_A.id)
    await flushAsync()

    // The server broadcasts everything to every client; a satellite only cares
    // about a couple of list-level events.
    for (let i = 0; i < 10; i++) {
      getWs(0).receive({
        type: 'event',
        event: 'chat:chunk',
        seq: i,
        payload: { session_id: 's1', text: 'x' },
      })
    }

    const late = vi.fn()
    await transport.listenOn(SAT_A.id, 'chat:chunk', late)
    expect(late).not.toHaveBeenCalled()
  })

  it('fires the disconnect callback registered before the focus id resolved', async () => {
    // App.tsx subscribes on first render, while the connection list is still
    // loading and getActiveConnectionId() still reads 'local'.
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({ ok: true, json: async () => ({}) })
    )
    const { transport, focus } = await loadMultiInstanceTransportModule()
    const onDisconnect = vi.fn()

    transport.onEstablishedWsDisconnect(onDisconnect)

    // The stored selection resolves to a remote once the list arrives.
    focus.id = SAT_A.id
    transport.connectTransport()
    await flushAsync()

    getWs(0).close()

    expect(onDisconnect).toHaveBeenCalledOnce()
  })
})
