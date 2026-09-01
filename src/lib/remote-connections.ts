import { useSyncExternalStore } from 'react'
// Circular import with environment.ts (it re-exports nothing from here at
// module scope); isNativeApp is only called after both modules evaluate.
import { isNativeApp } from './environment'
import { generateId } from './uuid'

export const LOCAL_CONNECTION_ID = 'local'

const CONNECTIONS_KEY = 'jean-remote-connections'
const ACTIVE_CONNECTION_KEY = 'jean-active-connection'
const SWITCHING_CONNECTION_KEY = 'jean-switching-connection-at'

export interface RemoteConnection {
  id: string
  name: string
  url: string
  /**
   * Access token. Optional: web clients load the list from the origin hub,
   * which masks tokens (write-only field). Native clients keep the real token
   * in their machine-local storage.
   */
  token?: string
  /** SSH user for local editors that open remote paths (Zed `ssh://`). */
  sshUser?: string
  /** SSH host/IP; falls back to Web Access URL hostname when omitted. */
  sshHost?: string
  /** SSH port (default 22 when omitted). */
  sshPort?: number
  /**
   * Aggregate this instance's sessions into the sidebar. Omitted means `true`:
   * connections created before the toggle existed keep aggregating.
   * When `false` the instance is switch-only — no background transport, no
   * sidebar section.
   */
  aggregateSessions?: boolean
}

export interface RemoteConnectionInput {
  name: string
  url: string
  /** Only sent when (re)entered; empty/omitted keeps the stored token. */
  token?: string
  sshUser?: string
  sshHost?: string
  sshPort?: number
  /** Omitted keeps the stored value (or the `true` default for a new one). */
  aggregateSessions?: boolean
}

/** Whether this instance's sessions show up in the sidebar. Missing = on. */
export function aggregatesSessions(connection: RemoteConnection): boolean {
  return connection.aggregateSessions !== false
}

/** Parse a user-entered SSH port string; empty → undefined. Throws on invalid. */
export function parseOptionalSshPort(raw: string): number | undefined {
  const trimmed = raw.trim()
  if (!trimmed) return undefined
  const port = Number(trimmed)
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('SSH port must be an integer between 1 and 65535.')
  }
  return port
}

const subscribers = new Set<() => void>()
let connectionsSnapshot: RemoteConnection[] = readConnections()
// Raw saved selection. Validation against the list is deferred to
// getActiveConnectionId() because in web mode the list arrives
// asynchronously from the server (initRemoteConnections).
let activeConnectionSnapshot =
  storage()?.getItem(ACTIVE_CONNECTION_KEY) || LOCAL_CONNECTION_ID

function notifySubscribers(): void {
  for (const subscriber of subscribers) subscriber()
}

function storage(): Storage | null {
  return typeof window === 'undefined' ? null : window.localStorage
}

function normalizeOptionalString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined
  const trimmed = value.trim()
  return trimmed || undefined
}

function normalizeOptionalPort(value: unknown): number | undefined {
  if (typeof value !== 'number' || !Number.isInteger(value)) return undefined
  if (value < 1 || value > 65535) return undefined
  return value
}

function normalizeConnection(item: unknown): RemoteConnection | null {
  if (!item || typeof item !== 'object') return null
  const record = item as Record<string, unknown>
  if (
    typeof record.id !== 'string' ||
    typeof record.name !== 'string' ||
    typeof record.url !== 'string'
  ) {
    return null
  }

  const connection: RemoteConnection = {
    id: record.id,
    name: record.name,
    url: record.url,
  }

  // Token is optional: the origin hub masks it in GET responses (write-only).
  if (typeof record.token === 'string' && record.token) {
    connection.token = record.token
  }

  const sshUser = normalizeOptionalString(record.sshUser)
  const sshHost = normalizeOptionalString(record.sshHost)
  const sshPort = normalizeOptionalPort(record.sshPort)
  if (sshUser) connection.sshUser = sshUser
  if (sshHost) connection.sshHost = sshHost
  if (sshPort) connection.sshPort = sshPort
  // Only the explicit opt-out is kept; anything else falls back to the default.
  if (record.aggregateSessions === false) connection.aggregateSessions = false

  return connection
}

function readConnections(): RemoteConnection[] {
  const raw = storage()?.getItem(CONNECTIONS_KEY)
  if (!raw) return []

  try {
    const parsed = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed
      .map(normalizeConnection)
      .filter((item): item is RemoteConnection => item !== null)
  } catch {
    return []
  }
}

function sshFieldsFromInput(input: RemoteConnectionInput): {
  sshUser?: string
  sshHost?: string
  sshPort?: number
} {
  const fields: {
    sshUser?: string
    sshHost?: string
    sshPort?: number
  } = {}
  const sshUser = normalizeOptionalString(input.sshUser)
  const sshHost = normalizeOptionalString(input.sshHost)
  const sshPort = normalizeOptionalPort(input.sshPort)
  if (sshUser) fields.sshUser = sshUser
  if (sshHost) fields.sshHost = sshHost
  // Only persist non-default ports; 22 is implied when omitted.
  if (sshPort && sshPort !== 22) fields.sshPort = sshPort
  return fields
}

/** Web clients store the list on the origin Jean server so every device
 * shares one configuration and remote tokens never persist in the browser.
 * Native apps keep localStorage (their WebView storage is machine-local). */
function usesServerConnectionStore(): boolean {
  if (typeof window === 'undefined' || isNativeApp()) return false
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return !(window as any).__JEAN_E2E_MOCK__
}

function serverConnectionsUrl(): string {
  const urlToken = new URLSearchParams(window.location.search).get('token')
  const token = urlToken || storage()?.getItem('jean-http-token') || ''
  const params = token ? `?token=${encodeURIComponent(token)}` : ''
  return `${window.location.origin}/api/remote-connections${params}`
}

async function pushServerConnections(
  connections: RemoteConnection[]
): Promise<void> {
  const response = await fetch(serverConnectionsUrl(), {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(connections),
  })
  if (!response.ok) {
    throw new Error('Failed to save connections to the Jean server.')
  }
}

function commitConnections(connections: RemoteConnection[]): void {
  connectionsSnapshot = connections
  notifySubscribers()
}

async function persistConnections(
  connections: RemoteConnection[]
): Promise<void> {
  if (usesServerConnectionStore()) {
    // Server write must complete before commit: callers reload the page
    // right after, which would abort an in-flight PUT.
    await pushServerConnections(connections)
    commitConnections(connections)
    return
  }
  storage()?.setItem(CONNECTIONS_KEY, JSON.stringify(connections))
  commitConnections(connections)
}

let initPromise: Promise<void> | null = null

/**
 * Load the connection list from the origin Jean server (web mode only).
 * Must resolve before the transport connects: the active remote's URL and
 * token come from this list. A pre-server-store localStorage list is
 * migrated up once, then removed from the browser.
 */
export function initRemoteConnections(): Promise<void> {
  if (!usesServerConnectionStore()) return Promise.resolve()
  initPromise ??= (async () => {
    try {
      const response = await fetch(serverConnectionsUrl())
      // Unauthenticated or older server: keep the localStorage fallback.
      if (!response.ok) return
      const parsed: unknown = await response.json()
      const serverList = (Array.isArray(parsed) ? parsed : [])
        .map(normalizeConnection)
        .filter((item): item is RemoteConnection => item !== null)

      const legacy = readConnections().filter(
        item => !serverList.some(existing => existing.id === item.id)
      )
      const merged = [...serverList, ...legacy]
      if (legacy.length > 0) await pushServerConnections(merged)
      storage()?.removeItem(CONNECTIONS_KEY)
      commitConnections(merged)
    } catch {
      // Server unreachable: keep whatever localStorage had.
    }
  })()
  return initPromise
}

export function parseRemoteConnectionInput(
  rawUrl: string,
  rawToken?: string
): { url: string; token: string } {
  let parsed: URL
  try {
    parsed = new URL(rawUrl.trim())
  } catch {
    throw new Error('Enter a valid HTTP or HTTPS URL.')
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Enter an HTTP or HTTPS URL.')
  }

  const token =
    rawToken?.trim() || parsed.searchParams.get('token')?.trim() || ''
  parsed.search = ''
  parsed.hash = ''
  parsed.pathname = parsed.pathname.replace(/\/+$/, '')

  return { url: parsed.toString().replace(/\/$/, ''), token }
}

export function getRemoteConnections(): RemoteConnection[] {
  return connectionsSnapshot
}

export async function addRemoteConnection(
  input: RemoteConnectionInput
): Promise<RemoteConnection> {
  const normalized = parseRemoteConnectionInput(input.url, input.token)
  const connection: RemoteConnection = {
    id: generateId(),
    name: input.name.trim() || new URL(normalized.url).hostname,
    url: normalized.url,
    ...sshFieldsFromInput(input),
  }
  if (normalized.token) connection.token = normalized.token
  if (input.aggregateSessions === false) connection.aggregateSessions = false
  await persistConnections([...getRemoteConnections(), connection])
  return connection
}

export async function updateRemoteConnection(
  id: string,
  input: RemoteConnectionInput
): Promise<RemoteConnection> {
  const normalized = parseRemoteConnectionInput(input.url, input.token)
  const connections = getRemoteConnections()
  const existing = connections.find(connection => connection.id === id)
  if (!existing) {
    throw new Error('Remote connection not found.')
  }
  const updated: RemoteConnection = {
    id,
    name: input.name.trim() || new URL(normalized.url).hostname,
    url: normalized.url,
    ...sshFieldsFromInput(input),
  }
  // Write-only token: overwrite only when a new token was entered; otherwise
  // keep the previously stored one (web clients never see the masked token).
  const token = normalized.token || existing.token
  if (token) updated.token = token
  // The edit form does not own this flag: an omitted value keeps the toggle
  // where the sidebar list left it.
  const aggregate = input.aggregateSessions ?? existing.aggregateSessions
  if (aggregate === false) updated.aggregateSessions = false
  await persistConnections(
    connections.map(connection => (connection.id === id ? updated : connection))
  )
  return updated
}

export async function removeRemoteConnection(id: string): Promise<void> {
  await persistConnections(
    getRemoteConnections().filter(connection => connection.id !== id)
  )
  // Compare the raw saved id: the lazy getter already resolves a removed
  // connection to 'local', which would skip clearing the stored selection.
  if (activeConnectionSnapshot === id) selectConnection(LOCAL_CONNECTION_ID)
}

/**
 * Turn sidebar aggregation on or off for one connection.
 *
 * Kept out of `updateRemoteConnection` on purpose: the toggle lives in the
 * connections list, not in the edit form, and must not require re-entering a
 * token to flip.
 */
export async function setConnectionAggregation(
  id: string,
  enabled: boolean
): Promise<void> {
  const connections = getRemoteConnections()
  const existing = connections.find(connection => connection.id === id)
  if (!existing || aggregatesSessions(existing) === enabled) return
  await persistConnections(
    connections.map(connection => {
      if (connection.id !== id) return connection
      const next = { ...connection }
      if (enabled) delete next.aggregateSessions
      else next.aggregateSessions = false
      return next
    })
  )
}

export function getActiveConnectionId(): string {
  if (activeConnectionSnapshot === LOCAL_CONNECTION_ID) {
    return LOCAL_CONNECTION_ID
  }
  return connectionsSnapshot.some(
    connection => connection.id === activeConnectionSnapshot
  )
    ? activeConnectionSnapshot
    : LOCAL_CONNECTION_ID
}

export function getActiveRemoteConnection(): RemoteConnection | null {
  const activeId = getActiveConnectionId()
  if (activeId === LOCAL_CONNECTION_ID) return null
  return (
    getRemoteConnections().find(connection => connection.id === activeId) ??
    null
  )
}

export function selectConnection(id: string): void {
  const selected =
    id === LOCAL_CONNECTION_ID ||
    getRemoteConnections().some(connection => connection.id === id)
      ? id
      : LOCAL_CONNECTION_ID
  activeConnectionSnapshot = selected
  storage()?.setItem(ACTIVE_CONNECTION_KEY, selected)
  notifySubscribers()
}

export function markConnectionSwitch(): void {
  if (typeof window !== 'undefined') {
    window.sessionStorage.setItem(SWITCHING_CONNECTION_KEY, String(Date.now()))
  }
}

export function isConnectionSwitchPending(): boolean {
  if (typeof window === 'undefined') return false
  const switchedAt = Number(
    window.sessionStorage.getItem(SWITCHING_CONNECTION_KEY) ?? 0
  )
  return switchedAt > 0 && Date.now() - switchedAt < 30_000
}

export function clearConnectionSwitch(): void {
  if (typeof window !== 'undefined') {
    window.sessionStorage.removeItem(SWITCHING_CONNECTION_KEY)
  }
}

export function useRemoteConnections(): RemoteConnection[] {
  return useSyncExternalStore(
    callback => {
      subscribers.add(callback)
      return () => subscribers.delete(callback)
    },
    () => connectionsSnapshot,
    () => []
  )
}
