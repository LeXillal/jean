import { beforeEach, describe, expect, it, vi } from 'vitest'

const { isNativeApp } = vi.hoisted(() => ({
  isNativeApp: vi.fn(() => true),
}))

vi.mock('./environment', () => ({ isNativeApp }))

const fetchMock = vi.fn()

/** The module keeps snapshots at module scope; reload it per test so each
 * test sees the localStorage/fetch state it just prepared. */
async function loadModule() {
  vi.resetModules()
  return await import('./remote-connections')
}

function jsonResponse(body: unknown, ok = true) {
  return {
    ok,
    json: async () => body,
  } as Response
}

describe('remote connections', () => {
  // The global test setup replaces localStorage with inert vi.fn() mocks;
  // back them with a real store so persistence assertions mean something.
  const store = new Map<string, string>()

  beforeEach(() => {
    store.clear()
    sessionStorage.clear()
    vi.clearAllMocks()
    vi.mocked(localStorage.getItem).mockImplementation(
      (key: string) => store.get(key) ?? null
    )
    vi.mocked(localStorage.setItem).mockImplementation(
      (key: string, value: string) => {
        store.set(key, value)
      }
    )
    vi.mocked(localStorage.removeItem).mockImplementation((key: string) => {
      store.delete(key)
    })
    isNativeApp.mockReturnValue(true)
    vi.stubGlobal('fetch', fetchMock)
  })

  it('extracts a token from a complete Web Access URL', async () => {
    const { parseRemoteConnectionInput } = await loadModule()
    expect(
      parseRemoteConnectionInput('https://jean.example.com/?token=secret', '')
    ).toEqual({ url: 'https://jean.example.com', token: 'secret' })
  })

  it('accepts a separate token and normalizes the URL', async () => {
    const { parseRemoteConnectionInput } = await loadModule()
    expect(
      parseRemoteConnectionInput('http://server.local:3456///', ' token ')
    ).toEqual({ url: 'http://server.local:3456', token: 'token' })
  })

  it('rejects unsupported URL schemes', async () => {
    const { parseRemoteConnectionInput } = await loadModule()
    expect(() => parseRemoteConnectionInput('ftp://server', 'token')).toThrow(
      'HTTP or HTTPS'
    )
  })

  it('persists CRUD operations and the active selection (native)', async () => {
    const {
      addRemoteConnection,
      getActiveConnectionId,
      getActiveRemoteConnection,
      getRemoteConnections,
      removeRemoteConnection,
      selectConnection,
      updateRemoteConnection,
    } = await loadModule()

    const remote = await addRemoteConnection({
      name: 'Build server',
      url: 'https://jean.example.com?token=first',
      token: '',
    })

    expect(getRemoteConnections()).toEqual([remote])

    selectConnection(remote.id)
    expect(getActiveConnectionId()).toBe(remote.id)
    expect(getActiveRemoteConnection()).toEqual(remote)

    const updated = await updateRemoteConnection(remote.id, {
      name: 'Production',
      url: remote.url,
      token: 'second',
    })
    expect(getRemoteConnections()).toEqual([updated])

    await removeRemoteConnection(remote.id)
    expect(getRemoteConnections()).toEqual([])
    expect(getActiveConnectionId()).toBe('local')
    // Native mode never talks to a server store.
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('marks an intentional switch so unload cleanup can be skipped', async () => {
    const { clearConnectionSwitch, isConnectionSwitchPending, markConnectionSwitch } =
      await loadModule()

    markConnectionSwitch()
    expect(isConnectionSwitchPending()).toBe(true)

    clearConnectionSwitch()
    expect(isConnectionSwitchPending()).toBe(false)
  })

  it('persists optional SSH fields for remote editor open', async () => {
    const { addRemoteConnection, getRemoteConnections, updateRemoteConnection } =
      await loadModule()

    const remote = await addRemoteConnection({
      name: 'Build server',
      url: 'https://jean.example.com?token=first',
      token: '',
      sshUser: 'ubuntu',
      sshHost: '192.168.1.50',
      sshPort: 2222,
    })

    expect(remote).toMatchObject({
      sshUser: 'ubuntu',
      sshHost: '192.168.1.50',
      sshPort: 2222,
    })
    expect(getRemoteConnections()[0]).toMatchObject({
      sshUser: 'ubuntu',
      sshHost: '192.168.1.50',
      sshPort: 2222,
    })

    const updated = await updateRemoteConnection(remote.id, {
      name: remote.name,
      url: remote.url,
      token: 'second',
      sshUser: 'deploy',
      sshHost: '192.168.1.50',
      sshPort: 22,
    })
    expect(updated.sshUser).toBe('deploy')
    // Default SSH port is not stored.
    expect(updated.sshPort).toBeUndefined()
  })

  describe('web mode (server-side connection store)', () => {
    const serverEntry = {
      id: 'srv-1',
      name: 'ses-temps',
      url: 'https://huguette.example:8443',
      token: 'remote-token',
    }

    beforeEach(() => {
      isNativeApp.mockReturnValue(false)
      localStorage.setItem('jean-http-token', 'origin-token')
    })

    it('loads the list from the origin server and resolves the saved selection', async () => {
      localStorage.setItem('jean-active-connection', 'srv-1')
      fetchMock.mockResolvedValueOnce(jsonResponse([serverEntry]))

      const module = await loadModule()
      await module.initRemoteConnections()

      expect(fetchMock).toHaveBeenCalledTimes(1)
      const requestedUrl = String(fetchMock.mock.calls[0]?.[0])
      expect(requestedUrl).toContain('/api/remote-connections')
      expect(requestedUrl).toContain('token=origin-token')

      expect(module.getRemoteConnections()).toEqual([serverEntry])
      expect(module.getActiveRemoteConnection()).toEqual(serverEntry)
    })

    it('resolves the saved selection to local until the server list arrives', async () => {
      localStorage.setItem('jean-active-connection', 'srv-1')
      fetchMock.mockResolvedValue(jsonResponse([serverEntry]))

      const module = await loadModule()
      expect(module.getActiveConnectionId()).toBe('local')

      await module.initRemoteConnections()
      expect(module.getActiveConnectionId()).toBe('srv-1')
    })

    it('migrates a legacy localStorage list to the server once', async () => {
      const legacy = {
        id: 'legacy-1',
        name: 'pixelguess',
        url: 'http://192.168.1.63:3456',
        token: 'legacy-token',
      }
      localStorage.setItem('jean-remote-connections', JSON.stringify([legacy]))
      fetchMock
        .mockResolvedValueOnce(jsonResponse([serverEntry]))
        .mockResolvedValueOnce(jsonResponse({ ok: true }))

      const module = await loadModule()
      await module.initRemoteConnections()

      expect(fetchMock).toHaveBeenCalledTimes(2)
      const putCall = fetchMock.mock.calls[1]
      expect(putCall?.[1]).toMatchObject({ method: 'PUT' })
      expect(JSON.parse(putCall?.[1]?.body as string)).toEqual([
        serverEntry,
        legacy,
      ])

      expect(localStorage.getItem('jean-remote-connections')).toBeNull()
      expect(module.getRemoteConnections()).toEqual([serverEntry, legacy])
    })

    it('writes mutations to the server, never to localStorage', async () => {
      fetchMock
        .mockResolvedValueOnce(jsonResponse([]))
        .mockResolvedValueOnce(jsonResponse({ ok: true }))

      const module = await loadModule()
      await module.initRemoteConnections()

      const added = await module.addRemoteConnection({
        name: 'jean',
        url: 'http://192.168.1.78:3456',
        token: 'tok',
      })

      const putCall = fetchMock.mock.calls[1]
      expect(putCall?.[1]).toMatchObject({ method: 'PUT' })
      expect(JSON.parse(putCall?.[1]?.body as string)).toEqual([added])
      expect(localStorage.getItem('jean-remote-connections')).toBeNull()
      expect(module.getRemoteConnections()).toEqual([added])
    })

    it('does not commit a mutation the server rejected', async () => {
      fetchMock
        .mockResolvedValueOnce(jsonResponse([serverEntry]))
        .mockResolvedValueOnce(jsonResponse(null, false))

      const module = await loadModule()
      await module.initRemoteConnections()

      await expect(
        module.addRemoteConnection({
          name: 'jean',
          url: 'http://192.168.1.78:3456',
          token: 'tok',
        })
      ).rejects.toThrow('Failed to save connections')
      expect(module.getRemoteConnections()).toEqual([serverEntry])
    })

    it('keeps the localStorage fallback when the server request fails', async () => {
      const legacy = {
        id: 'legacy-1',
        name: 'pixelguess',
        url: 'http://192.168.1.63:3456',
        token: 'legacy-token',
      }
      localStorage.setItem('jean-remote-connections', JSON.stringify([legacy]))
      fetchMock.mockRejectedValueOnce(new Error('network down'))

      const module = await loadModule()
      await module.initRemoteConnections()

      expect(module.getRemoteConnections()).toEqual([legacy])
      expect(localStorage.getItem('jean-remote-connections')).not.toBeNull()
    })
  })
})
