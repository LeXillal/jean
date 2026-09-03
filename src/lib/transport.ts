/**
 * Transport abstraction layer.
 *
 * Drop-in replacements for @tauri-apps/api/core invoke() and
 * @tauri-apps/api/event listen(). Routes through Tauri IPC when
 * running as a native app, or WebSocket when running in a browser.
 */

import { useSyncExternalStore } from 'react'
import {
  isNativeApp,
  isNativeOpenAllowed,
  setWebAccessEnabled,
  setWsConnected,
} from './environment'
import { generateId } from './uuid'
import { isServerWindows } from './platform'
import {
  LOCAL_CONNECTION_ID,
  getActiveConnectionId,
  getActiveRemoteConnection,
  getRemoteConnections,
  type RemoteConnection,
} from './remote-connections'
import { prepareRemoteEditorOpenArgs } from './remote-editor'
import {
  fetchRemoteServerInfoFromAuthUrl,
  warnRemoteVersionMismatch,
  type RemoteServerInfo,
} from './remote-version'

/**
 * Why the browser session is not authenticated yet.
 *
 * - `signed-out`  — no token has been presented; this is the normal first
 *   visit and a sign-in prompt, not a failure.
 * - `rejected`    — a token was presented and the server refused it.
 * - `unreachable` — the server could not be reached or dropped the session.
 */
export type WsAuthReason =
  | 'signed-out'
  | 'rejected'
  | 'unreachable'
  /** The token was accepted; the server is waiting for a 2FA code. */
  | 'code-required'

export function usesWebSocketBackend(): boolean {
  return !isNativeApp() || getActiveRemoteConnection() !== null
}

/**
 * Resolve an instance id to its remote connection.
 *
 * `LOCAL_CONNECTION_ID` (and any id no longer in the list) means "the origin
 * hub itself" and resolves to `null`, matching {@link getActiveRemoteConnection}.
 */
export function connectionForInstance(
  instanceId: string
): RemoteConnection | null {
  if (instanceId === LOCAL_CONNECTION_ID) return null
  return getRemoteConnections().find(item => item.id === instanceId) ?? null
}

/**
 * Base URL for backend HTTP/WS requests in web-backend mode.
 *
 * - Local web (no remote): the origin hub itself.
 * - Web + remote: relayed through the origin hub proxy at `/remote/<id>`.
 *   The browser never holds the remote's own URL/token; the hub relays with
 *   the hub token only.
 * - Native app + remote: direct access to the remote's own URL (unchanged).
 */
function backendBaseUrlFor(remote: RemoteConnection | null): string {
  if (!remote) return window.location.origin
  // Native desktop keeps its direct connection to the remote server.
  if (isNativeApp()) return remote.url
  // Web clients relay everything through the origin hub proxy.
  return `${window.location.origin}/remote/${remote.id}`
}

function getWebBackendBaseUrl(): string {
  return backendBaseUrlFor(getActiveRemoteConnection())
}

/**
 * Base URL for building `/api/...` asset URLs.
 *
 * Mirrors {@link getWebBackendBaseUrl} but stays relative ('') in local web
 * mode so same-origin asset URLs remain relative (no behavior change).
 */
function getWebAssetBaseUrl(): string {
  return getActiveRemoteConnection() ? getWebBackendBaseUrl() : ''
}

function backendTokenFor(remote: RemoteConnection | null): string {
  // Native desktop connecting directly to a remote uses the remote's own token.
  if (remote && isNativeApp()) return remote.token ?? ''
  // Web mode (local or remote via proxy): always the hub token. The remote's
  // token is never exposed to the browser anymore.
  const urlToken = new URLSearchParams(window.location.search).get('token')
  return urlToken || localStorage.getItem('jean-http-token') || ''
}

function getWebBackendToken(): string {
  return backendTokenFor(getActiveRemoteConnection())
}

/**
 * Credential query string for URLs the browser fetches on its own — `<img>`
 * sources and the like, which can carry neither a header nor, cross-origin, a
 * cookie.
 *
 * Prefers the session: on a server with a second factor enrolled the raw token
 * no longer authorizes anything, so a token-bearing asset URL would 401.
 */
function assetAuthParams(): string {
  const remote = getActiveRemoteConnection()
  const session = remoteSessionFor(remote)
  if (session) return `?session=${encodeURIComponent(session)}`
  const token = backendTokenFor(remote)
  return token ? `?token=${encodeURIComponent(token)}` : ''
}

function backendUrlFor(remote: RemoteConnection | null, path: string): string {
  const base = `${backendBaseUrlFor(remote).replace(/\/+$/, '')}/`
  return new URL(path.replace(/^\/+/, ''), base).toString()
}

function backendUrl(path: string): string {
  return backendUrlFor(getActiveRemoteConnection(), path)
}

/**
 * Build the proxied `/api/auth` probe URL for a registered remote connection.
 *
 * Web clients no longer hold the remote's token, so version probes must go
 * through the origin hub proxy with the hub token.
 */
export function proxiedRemoteAuthUrl(id: string): string {
  const token = getWebBackendToken()
  const base = `${window.location.origin}/remote/${id}/`
  const authUrl = new URL('api/auth', base)
  if (token) authUrl.searchParams.set('token', token)
  return authUrl.toString()
}

/**
 * Probe a registered remote connection's server info, choosing the right
 * transport: native desktop talks to the remote directly with its own token;
 * web clients relay through the origin hub proxy with the hub token.
 */
export async function probeConnectionServerInfo(connection: {
  id: string
  url: string
  token?: string
}): Promise<RemoteServerInfo> {
  if (isNativeApp()) {
    const base = `${connection.url.replace(/\/+$/, '')}/`
    const authUrl = new URL('api/auth', base)
    if (connection.token) authUrl.searchParams.set('token', connection.token)
    return fetchRemoteServerInfoFromAuthUrl(authUrl.toString())
  }
  return fetchRemoteServerInfoFromAuthUrl(proxiedRemoteAuthUrl(connection.id))
}

// ---------------------------------------------------------------------------
// Native session credentials
// ---------------------------------------------------------------------------
//
// A server with a second factor enrolled stops accepting the raw token on its
// endpoints: the token becomes the first factor of `/api/login` and nothing
// more. Browsers come out of that login holding an HttpOnly cookie; the native
// app cannot (it talks cross-origin from `tauri://localhost`), so it asks for
// the session value directly and carries it itself. Same signed value, same
// server-side verification — and, unlike the token, revocable per device.

function remoteSessionKey(id: string): string {
  return `jean-remote-session:${id}`
}

/** The session this client holds for a remote, if it has logged in before. */
function remoteSessionFor(remote: RemoteConnection | null): string | null {
  if (!remote || !isNativeApp()) return null
  return localStorage.getItem(remoteSessionKey(remote.id))
}

function storeRemoteSession(id: string, session: string): void {
  localStorage.setItem(remoteSessionKey(id), session)
}

export function clearRemoteSession(id: string): void {
  localStorage.removeItem(remoteSessionKey(id))
}

/** What a native sign-in attempt against a remote produced. */
export type RemoteLoginResult =
  | { ok: true }
  /** Token fine, second factor needed (or the submitted code was refused). */
  | { ok: false; codeRequired: true; error: string }
  /** Token refused, or the server is too old to have `/api/login`. */
  | { ok: false; codeRequired: false; error: string; legacy: boolean }

/**
 * Exchange a remote's token (plus a 2FA code when asked) for a session value.
 *
 * `legacy: true` means the endpoint is missing, not that the credentials were
 * wrong — the caller falls back to raw-token auth, which such a server still
 * accepts because it has no second factor to enforce.
 */
export async function loginRemoteForSession(
  remote: RemoteConnection,
  code?: string
): Promise<RemoteLoginResult> {
  const url = new URL(
    'api/login',
    `${remote.url.replace(/\/+$/, '')}/`
  ).toString()
  let res: Response
  try {
    res = await fetchBackendFor(remote, url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        token: remote.token ?? '',
        code,
        transport: 'header',
      }),
    })
  } catch {
    return {
      ok: false,
      codeRequired: false,
      error: 'Could not reach the server.',
      legacy: true,
    }
  }

  if (res.ok) {
    const body = (await res.json().catch(() => null)) as {
      session?: string
    } | null
    if (!body?.session) {
      // An older server answers `{ok:true}` with a cookie we cannot hold.
      return {
        ok: false,
        codeRequired: false,
        error: 'Server did not return a session.',
        legacy: true,
      }
    }
    storeRemoteSession(remote.id, body.session)
    return { ok: true }
  }

  if (res.status === 404 || res.status === 405) {
    return {
      ok: false,
      codeRequired: false,
      error: 'Server has no session endpoint.',
      legacy: true,
    }
  }

  const body = (await res.json().catch(() => null)) as {
    error?: string
    code_required?: boolean
  } | null
  if (body?.code_required) {
    return {
      ok: false,
      codeRequired: true,
      error: body.error ?? 'Enter the code from your authenticator app.',
      }
  }
  return {
    ok: false,
    codeRequired: false,
    error: body?.error ?? 'That access token was refused.',
    legacy: false,
  }
}

/**
 * Finish a native sign-in that stopped on the second factor. On success the
 * page reloads, which is how every transport picks the new session up.
 */
export async function submitRemoteTwoFactorCode(
  remote: RemoteConnection,
  code: string
): Promise<RemoteLoginResult> {
  const result = await loginRemoteForSession(remote, code)
  if (result.ok) window.location.reload()
  return result
}

function fetchBackendFor(
  remote: RemoteConnection | null,
  url: string,
  init?: RequestInit
): Promise<Response> {
  // Same-origin hub requests have no timeout; a relayed hop can hang on a
  // remote that stopped answering, so it gets an abort budget.
  if (!remote) return fetch(url, init)

  const session = remoteSessionFor(remote)
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), 12_000)
  return fetch(url, {
    ...init,
    headers: session
      ? { ...init?.headers, 'X-Jean-Session': session }
      : init?.headers,
    signal: controller.signal,
  }).finally(() => clearTimeout(timeout))
}

/**
 * A hub token arriving in the page URL is exchanged for an HttpOnly session
 * cookie exactly once per load; the reload that follows re-authenticates every
 * transport from that cookie. Module-scoped so concurrent transports racing to
 * connect do not each fire the exchange.
 */
let urlTokenCookieExchangeStarted = false

/**
 * Trade a hub token supplied in the URL for an HttpOnly session cookie, exactly
 * like the sign-in form (see `handleWsAuthTokenSubmit`). This keeps the
 * long-lived hub token out of localStorage (where any XSS could read it) and
 * out of the WebSocket/auth query string. Web mode only — native builds have no
 * same-origin cookie endpoint and keep the legacy localStorage token instead.
 */
async function exchangeHubUrlTokenForCookie(token: string): Promise<void> {
  try {
    const res = await fetch(`${window.location.origin}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      body: JSON.stringify({ token }),
    })
    if (res.ok) {
      // The cookie now carries auth; the token must not linger anywhere JS can
      // read it back.
      localStorage.removeItem('jean-http-token')
      window.location.reload()
      return
    }
  } catch {
    // Older server without /api/login, or offline — fall through to the legacy
    // token path so the client can still connect (or surface the auth error).
  }
  localStorage.setItem('jean-http-token', token)
  window.location.reload()
}

function fetchBackend(url: string): Promise<Response> {
  return fetchBackendFor(getActiveRemoteConnection(), url)
}

// ---------------------------------------------------------------------------
// File source URL conversion (drop-in for Tauri's convertFileSrc)
// ---------------------------------------------------------------------------

// Cache for the server's app data directory path (set from init data or hook).
// Used by convertFileSrc in browser mode to build /api/files/ URLs.
let _appDataDir: string | null = null

/** Set the app data directory path for browser-mode file URL conversion. */
export function setAppDataDir(dir: string): void {
  // Normalize: ensure trailing separator for reliable startsWith matching
  _appDataDir = dir.endsWith('/') || dir.endsWith('\\') ? dir : `${dir}/`
}

/**
 * Convert a filesystem path to a URL loadable by the webview.
 * Re-implements Tauri's convertFileSrc() as pure string manipulation
 * to avoid a static import of @tauri-apps/api/core (which crashes in
 * browser mode because it checks for __TAURI_INTERNALS__ on load).
 *
 * In browser mode, converts to /api/files/ URLs served by the HTTP server.
 */
export function convertFileSrc(filePath: string, protocol = 'asset'): string {
  if (!usesWebSocketBackend()) {
    // Use Tauri's native implementation which correctly percent-encodes paths
    // on all platforms (JS encodeURIComponent misses dots/hyphens/underscores
    // that Tauri's Rust encoder expects on Windows).
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const internals = (window as any).__TAURI_INTERNALS__
    if (internals?.convertFileSrc) {
      return internals.convertFileSrc(filePath, protocol)
    }
    // Fallback (should not reach in native app)
    const path = encodeURIComponent(filePath)
    return isServerWindows()
      ? `https://${protocol}.localhost/${path}`
      : `${protocol}://localhost/${path}`
  }

  // Browser mode: convert server filesystem path to /api/files/ URL
  const params = assetAuthParams()
  const base = getWebAssetBaseUrl()

  // Try exact prefix match with cached app data dir
  if (_appDataDir && filePath.startsWith(_appDataDir)) {
    const relativePath = filePath.substring(_appDataDir.length)
    return `${base}/api/files/${encodeURI(relativePath)}${params}`
  }

  // Fallback: detect app data dir marker in path (works before _appDataDir is set)
  for (const marker of ['com.jean.desktop/', 'com.jean.desktop\\']) {
    const idx = filePath.indexOf(marker)
    if (idx !== -1) {
      const relativePath = filePath.substring(idx + marker.length)
      return `${base}/api/files/${encodeURI(relativePath)}${params}`
    }
  }

  // Last resort: return as-is (will likely not render, but won't crash)
  return filePath
}

/**
 * Convert an absolute project/worktree file path to a browser-loadable URL.
 * Native mode can use Tauri's asset protocol directly; browser mode uses the
 * authenticated project-file endpoint, which validates the path against known
 * project/worktree roots before serving it.
 */
export function convertProjectFileSrc(filePath: string): string {
  if (!usesWebSocketBackend()) {
    return convertFileSrc(filePath)
  }

  const params = assetAuthParams()
  const base = getWebAssetBaseUrl()
  return `${base}/api/project-files/${encodeURIComponent(filePath)}${params}`
}

/** Unlisten function type — compatible with Tauri's UnlistenFn. */
export type UnlistenFn = () => void

function containNativeUnlisten(
  unlisten: () => void | Promise<void>
): UnlistenFn {
  let active = true
  return () => {
    if (!active) return
    active = false
    try {
      void Promise.resolve(unlisten()).catch(() => {
        // Page teardown can remove Tauri's listener registry first.
      })
    } catch {
      // Page teardown can remove Tauri's listener registry first.
    }
  }
}

const DESKTOP_ONLY_COMMANDS = new Set([
  'set_window_vibrancy',
  'send_native_notification',
  'read_clipboard_image',
  'write_clipboard_text',
  'read_clipboard_text',
  'save_dropped_image',
  'open_file_in_default_app',
  'open_worktree_in_finder',
  'open_project_worktrees_folder',
  'open_worktree_in_terminal',
  'open_worktree_in_editor',
  'open_project_on_github',
  'open_branch_on_github',
  'open_log_directory',
  'set_project_avatar',
  'start_http_server',
  'stop_http_server',
  'install_remote_jean_server',
  'browser_create',
  'browser_navigate',
  'browser_back',
  'browser_forward',
  'browser_reload',
  'browser_stop',
  'browser_set_bounds',
  'browser_set_visible',
  'browser_set_focus',
  'browser_get_url',
  'browser_close',
  'browser_report_title',
  'browser_enable_grab',
  'browser_report_grab_context',
  'get_active_browser_tabs',
  'has_active_browser_tab',
])

// These commands belong to the local desktop shell even when its application
// content is connected to a remote Jean backend.
const LOCAL_SHELL_COMMANDS = new Set([
  'set_window_vibrancy',
  'send_native_notification',
  'read_clipboard_image',
  'write_clipboard_text',
  'read_clipboard_text',
  // Quit confirmation must query the local process registry — remote sessions
  // survive client exit, and the remote WS may be down while loading/switching.
  'has_running_sessions',
  'install_remote_jean_server',
  'browser_create',
  'browser_navigate',
  'browser_back',
  'browser_forward',
  'browser_reload',
  'browser_stop',
  'browser_set_bounds',
  'browser_set_visible',
  'browser_set_focus',
  'browser_get_url',
  'browser_close',
  'browser_report_title',
  'browser_enable_grab',
  'browser_report_grab_context',
  'get_active_browser_tabs',
  'has_active_browser_tab',
])

// ---------------------------------------------------------------------------
// Public API (same signatures as Tauri)
// ---------------------------------------------------------------------------

/**
 * Call a backend command. Drop-in replacement for Tauri's invoke().
 */
export async function invoke<T>(
  command: string,
  args?: Record<string, unknown>
): Promise<T> {
  // E2E mock transport — route to in-memory handlers
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const e2eMock = (window as any).__JEAN_E2E_MOCK__
  if (e2eMock) {
    const handler = e2eMock.invokeHandlers[command]
    if (handler) return handler(args) as T
    console.warn(`[E2E] No mock for command: ${command}`)
    return null as T
  }

  // Native app + remote Jean: open remote paths in local Zed via ssh://
  // when the remote host cannot launch apps itself. Prefer the backend's
  // native-open path when available (e.g. headless on WSL, --allow-native-open)
  // so we don't bypass the WSL launcher with a broken Windows-side ssh:// remap.
  if (isNativeApp() && usesWebSocketBackend() && !isNativeOpenAllowed()) {
    const remote = getActiveRemoteConnection()
    if (remote) {
      const remapped = prepareRemoteEditorOpenArgs(command, args, remote)
      if (remapped) {
        const { invoke: tauriInvoke } = await import('@tauri-apps/api/core')
        return tauriInvoke<T>(command, remapped)
      }
    }
  }

  if (
    !usesWebSocketBackend() ||
    (isNativeApp() && LOCAL_SHELL_COMMANDS.has(command))
  ) {
    const { invoke: tauriInvoke } = await import('@tauri-apps/api/core')
    if (DESKTOP_ONLY_COMMANDS.has(command)) {
      return tauriInvoke<T>(command, args)
    }
    return tauriInvoke<T>('dispatch_core_command', {
      command,
      args: args ?? {},
    })
  }
  return focusedTransport().invoke<T>(command, args)
}

/**
 * Listen for backend events. Drop-in replacement for Tauri's listen().
 * Returns an unlisten function.
 */
export async function listen<T>(
  event: string,
  handler: (event: { payload: T }) => void
): Promise<() => void> {
  // E2E mock transport — route to in-memory event emitter
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const e2eMock = (window as any).__JEAN_E2E_MOCK__
  if (e2eMock) {
    const et = e2eMock.eventEmitter as EventTarget
    const wrapped = (e: Event) =>
      handler({ payload: (e as CustomEvent).detail })
    et.addEventListener(event, wrapped)
    return () => et.removeEventListener(event, wrapped)
  }

  if (!usesWebSocketBackend()) {
    const { listen: tauriListen } = await import('@tauri-apps/api/event')
    const unlisten = await tauriListen<T>(event, handler)
    return containNativeUnlisten(unlisten)
  }
  return focusedTransport().listen<T>(event, handler)
}

/** Listen for events emitted by the local desktop shell, even when connected
 * to a remote Jean backend. Browser clients have no local shell. */
export async function listenLocal<T>(
  event: string,
  handler: (event: { payload: T }) => void
): Promise<() => void> {
  if (!isNativeApp()) return listen(event, handler)
  const { listen: tauriListen } = await import('@tauri-apps/api/event')
  const unlisten = await tauriListen<T>(event, handler)
  return containNativeUnlisten(unlisten)
}

/**
 * Request buffered terminal events from the backend. Used by browser-mode
 * terminal reattachment after a full page refresh, when in-memory sequence
 * tracking was lost but the Rust PTY and replay buffer are still alive.
 */
export function requestTerminalReplay(terminalId: string, lastSeq = 0): void {
  if (!usesWebSocketBackend()) return
  focusedTransport().requestTerminalReplay(terminalId, lastSeq)
}

// ---------------------------------------------------------------------------
// Initial data preloading (used in browser mode)
// ---------------------------------------------------------------------------

export interface InitialData {
  projects?: unknown[]
  // Tiered payload: worktrees/sessions are present only for the selected
  // project; other projects are lazy-loaded by TanStack Query hooks on
  // navigation.
  worktreesByProject?: Record<string, unknown[]>
  sessionsByWorktree?: Record<string, unknown> // worktreeId -> WorktreeSessions
  activeSessions?: Record<string, unknown> // sessionId -> Session (with messages)
  runningSessions?: string[] // sessionIds with active CLI processes
  replayEvents?: BootstrapEvent[]
  preferences?: unknown
  uiState?: unknown
  appDataDir?: string
  serverPlatform?: 'mac' | 'windows' | 'linux'
  /** Server can launch host editor/finder/terminal (WSL or --allow-native-open). */
  nativeOpenAllowed?: boolean
  webBuildId?: string
  appVersion?: string
}

let initialDataPromise: Promise<InitialData | null> | null = null
let initialDataResolved = false

/**
 * Build the /api/init URL with the given query params.
 * Centralizes token and selected_project encoding.
 */
function buildInitUrl(opts: { selectedProjectId?: string | null }): string {
  const token = getWebBackendToken()
  const params = new URLSearchParams()
  if (token) params.set('token', token)
  if (opts.selectedProjectId) {
    params.set('selected_project', opts.selectedProjectId)
  }
  const qs = params.toString()
  const url = backendUrl('api/init')
  return qs ? `${url}?${qs}` : url
}

/**
 * Preload initial data via HTTP before WebSocket connects.
 * This allows the web view to show content immediately instead of
 * waiting for WebSocket connection + command round-trip.
 *
 * Returns null if preloading fails (app will fall back to WebSocket).
 *
 * @param selectedProjectId - Browser's currently-selected project id.
 *   Sent so the server scopes the init payload to just that project's
 *   worktrees/sessions. Falls back to `ui_state.json` on disk when absent.
 */
export async function preloadInitialData(
  selectedProjectId?: string | null
): Promise<InitialData | null> {
  if (!usesWebSocketBackend()) return null
  setWebAccessEnabled(true)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  if (typeof window !== 'undefined' && (window as any).__JEAN_E2E_MOCK__)
    return null
  if (initialDataPromise) return initialDataPromise

  initialDataPromise = (async () => {
    try {
      const url = buildInitUrl({ selectedProjectId })
      const response = await fetchBackend(url)
      if (!response.ok) {
        return null
      }
      const data = await response.json()
      initialDataResolved = true
      return data as InitialData
    } catch {
      return null
    }
  })()

  return initialDataPromise
}

/**
 * Check if initial data has been preloaded.
 */
export function hasPreloadedData(): boolean {
  return initialDataResolved
}

/**
 * Get the preloaded initial data if available (non-blocking).
 */
export function getPreloadedData(): InitialData | null {
  if (!initialDataResolved || !initialDataPromise) return null
  // Since initialDataResolved is true, the promise has resolved
  let result: InitialData | null = null
  initialDataPromise.then(data => {
    result = data
  })
  return result
}

// ---------------------------------------------------------------------------
// WebSocket Transport (used in browser mode)
// ---------------------------------------------------------------------------

interface PendingRequest {
  resolve: (data: unknown) => void
  reject: (error: Error) => void
  timeout: ReturnType<typeof setTimeout>
}

interface WsMessage {
  type: 'response' | 'error' | 'event' | 'heartbeat'
  id?: string
  data?: unknown
  error?: string
  event?: string
  payload?: unknown
  /** Monotonic sequence number for replay deduplication. */
  seq?: number
}

export interface BootstrapEvent {
  type: 'event'
  event: string
  payload: unknown
  seq?: number
}

class WsTransport {
  private ws: WebSocket | null = null
  private pending = new Map<string, PendingRequest>()
  private listeners = new Map<
    string,
    Set<(event: { payload: unknown }) => void>
  >()
  private connectRetryAttempt = 0
  private connectRetryTimer: ReturnType<typeof setTimeout> | null = null
  private connectWatchdog: ReturnType<typeof setTimeout> | null = null
  /** Fires once a socket has stayed open long enough to count as healthy. */
  private stabilityTimer: ReturnType<typeof setTimeout> | null = null
  /** Periodic check that we're seeing inbound traffic from the server.
   *  The server sends app-level heartbeats every 20s because browser JS cannot
   *  observe protocol ping/pong frames, so a 50s gap means the connection is dead. */
  private livenessTimer: ReturnType<typeof setInterval> | null = null
  private _lastInbound = 0
  private queue: { data: string; resolve: () => void }[] = []
  // Buffer for events that arrive before listeners are registered.
  // Covers the ~16ms gap between WS onopen and React effect listener setup.
  private eventBuffer = new Map<
    string,
    { msg: WsMessage; bufferedAt: number }[]
  >()
  private static readonly EVENT_BUFFER_MAX_AGE = 5_000
  private static readonly EVENT_BUFFER_MAX_SIZE = 50
  private _connected = false
  private _hasConnectedOnce = false
  private _connecting = false
  private _authError: string | null = null
  private _authReason: WsAuthReason | null = null
  private _subscribers = new Set<() => void>()
  private _connectEnabled = false
  /** Set by {@link dispose}; nothing may reopen a socket afterwards. */
  private _disposed = false
  /** True while this transport is the one that set the global connected flag. */
  private _drivesGlobalState = false
  /** Track last seen sequence numbers to deduplicate bootstrap replay. */
  private _lastSeqBySession = new Map<string, number>()
  /** Track terminal sequence numbers for explicit full-refresh replay. */
  private _lastSeqByTerminal = new Map<string, number>()

  /** Instance this transport talks to; `LOCAL_CONNECTION_ID` is the origin hub. */
  readonly instanceId: string

  constructor(instanceId: string) {
    this.instanceId = instanceId
    // Mobile browsers suspend background tabs and freeze JS timers. Check the
    // socket immediately on wake so a stale established connection triggers
    // the app reload without waiting for the periodic liveness timer.
    if (typeof window !== 'undefined') {
      document.addEventListener('visibilitychange', this.handleWake)
      window.addEventListener('online', this.handleWake)
      window.addEventListener('pageshow', this.handleWake)
    }
  }

  /**
   * The connection this transport targets, resolved on every read: in web mode
   * the connection list arrives asynchronously, so a transport can outlive the
   * moment its entry appears (or is edited).
   */
  private get remote(): RemoteConnection | null {
    return connectionForInstance(this.instanceId)
  }

  /**
   * Only the focused transport owns global UI state (the auth screen, the
   * "connection lost" reload). Satellites are background readers: they must
   * never blank the app because a secondary instance went down.
   */
  private get isFocused(): boolean {
    return this.instanceId === getActiveConnectionId()
  }

  get connected(): boolean {
    return this._connected
  }

  get authError(): string | null {
    return this._authError
  }

  /** Coarse state for the per-instance status indicator. */
  get status(): InstanceStatus {
    if (this._connected) return 'connected'
    if (this._authError) return 'auth-error'
    if (this._connecting || this.ws?.readyState === WebSocket.CONNECTING) {
      return 'connecting'
    }
    return this._hasConnectedOnce ? 'offline' : 'idle'
  }

  private setConnected(value: boolean): void {
    this._connected = value
    // Push the global flag down only if this transport is the one that raised
    // it. Reading `isFocused` on both edges would strand `setWsConnected(true)`
    // if focus moved between open and close.
    if (value ? this.isFocused : this._drivesGlobalState) {
      this._drivesGlobalState = value
      setWsConnected(value)
    }
    this.notifySubscribers()
  }

  // Overloads force every caller that sets a message to also classify it —
  // otherwise the UI cannot tell a first visit from a refused token or a
  // dead server, and silently picks the wrong screen.
  private setAuthError(error: null): void
  private setAuthError(error: string, reason: WsAuthReason): void
  private setAuthError(error: string | null, reason?: WsAuthReason): void {
    this._authError = error
    this._authReason = error === null ? null : (reason as WsAuthReason)
    this.notifySubscribers()
  }

  /** `_connecting` and the socket's CONNECTING state feed {@link status}. */
  private setConnecting(value: boolean): void {
    this._connecting = value
    this.notifySubscribers()
  }

  private notifySubscribers(): void {
    for (const cb of this._subscribers) cb()
    // Registry-level fan-out: hooks that follow "whatever is focused" or watch
    // every instance's status subscribe once, not per transport.
    notifyTransportRegistry()
  }

  /** Tear down sockets/timers for a connection that no longer exists. */
  dispose(): void {
    this._disposed = true
    this._connectEnabled = false
    this.clearConnectWatchdog()
    this.clearStabilityTimer()
    this.stopLivenessTimer()
    if (this.connectRetryTimer) {
      clearTimeout(this.connectRetryTimer)
      this.connectRetryTimer = null
    }
    if (typeof window !== 'undefined') {
      document.removeEventListener('visibilitychange', this.handleWake)
      window.removeEventListener('online', this.handleWake)
      window.removeEventListener('pageshow', this.handleWake)
    }
    try {
      this.ws?.close()
    } catch {
      // Already closing or never opened.
    }
    this.ws = null
    this.listeners.clear()
    this.eventBuffer.clear()
    // Fail callers now instead of leaving them on the 60s command timeout, and
    // drop anything queued so a disposed transport cannot replay it.
    for (const [, pending] of this.pending.entries()) {
      clearTimeout(pending.timeout)
      pending.reject(new Error('Connection was removed'))
    }
    this.pending.clear()
    this.queue = []
  }

  /** Subscribe to state changes. Returns an unsubscribe function. */
  subscribe(callback: () => void): () => void {
    this._subscribers.add(callback)
    return () => this._subscribers.delete(callback)
  }

  /** Get current connection snapshot for useSyncExternalStore. */
  getSnapshot(): boolean {
    return this._connected
  }

  /** Get current auth error snapshot for useSyncExternalStore. */
  getAuthErrorSnapshot(): string | null {
    return this._authError
  }

  /** Get why authentication is pending, for useSyncExternalStore. */
  getAuthReasonSnapshot(): WsAuthReason | null {
    return this._authReason
  }

  /** Connect to the WebSocket server (validates token first). */
  connect(): void {
    if (!this._connectEnabled || this._disposed) return
    // The FOCUSED transport recovers through a full page reload, never a
    // second in-memory WebSocket connection: the bootstrap is what rebuilds
    // in-flight streams and replay sequences. Satellites carry no such state,
    // so they reconnect in place — a secondary instance going down must not
    // drag the whole app through a reload.
    if (this._hasConnectedOnce && !this._connected && this.isFocused) return
    if (
      this._connecting ||
      this.ws?.readyState === WebSocket.OPEN ||
      this.ws?.readyState === WebSocket.CONNECTING
    )
      return

    // Native desktop pointing directly at a remote uses the remote's own token;
    // every web client (local or remote via proxy) uses the hub token.
    const remote = this.remote
    const isDirectNativeRemote = Boolean(remote) && isNativeApp()
    const token = backendTokenFor(remote)
    const urlToken = new URLSearchParams(window.location.search).get('token')

    // A hub token in the URL must not become a long-lived, XSS-readable
    // localStorage entry (nor keep riding in the WS/auth query string).
    if (!isDirectNativeRemote && urlToken) {
      // Strip the token from the URL first (history/bookmark hygiene), so the
      // post-exchange reload lands on a clean URL and cannot loop.
      const url = new URL(window.location.href)
      url.searchParams.delete('token')
      window.history.replaceState({}, '', url.toString())

      if (!isNativeApp()) {
        // Web: exchange the URL token for an HttpOnly session cookie, then let
        // the reload re-authenticate from the cookie. Run once — the first
        // transport to boot drives it for all of them.
        if (!urlTokenCookieExchangeStarted) {
          urlTokenCookieExchangeStarted = true
          void exchangeHubUrlTokenForCookie(urlToken)
        }
        return
      }

      // Native builds have no same-origin cookie endpoint; keep the token in
      // machine-local storage as before.
      localStorage.setItem('jean-http-token', urlToken)
    }

    this.setConnecting(true)

    this.validateAndConnect(token).finally(() => {
      this.setConnecting(false)
    })
  }

  enableConnect(): void {
    if (this._connectEnabled) return
    this._connectEnabled = true
    this.connect()
  }

  /**
   * @param afterLogin set when this call follows a successful session login, so
   *   a second refusal cannot start another login and loop.
   */
  private async validateAndConnect(
    token: string,
    afterLogin = false
  ): Promise<void> {
    const remote = this.remote
    const session = remoteSessionFor(remote)
    const authBaseUrl = backendUrlFor(remote, 'api/auth')
    // A session travels in a header (added by `fetchBackendFor`), so it never
    // needs to ride in the query string the way the token does.
    const authUrl =
      !session && token
        ? `${authBaseUrl}?token=${encodeURIComponent(token)}`
        : authBaseUrl

    try {
      const res = await fetchBackendFor(remote, authUrl)
      if (!res.ok) {
        // A satellite has no UI to prompt with, so it must tell "refused" from
        // "not answering". Only 401/403 is a credential problem worth stopping
        // for; anything else (a 502 from the proxy when the remote is down) is
        // transient and has to keep retrying, or the instance never returns.
        if (!this.isFocused && res.status !== 401 && res.status !== 403) {
          this.setAuthError(null)
          this.scheduleConnectRetry()
          return
        }
        // Credentials refused. On a native remote that can simply mean the
        // server now wants a session instead of a raw token — a second factor
        // was enrolled, or the session we held was revoked. Try once to get a
        // fresh one before treating this as the user's problem.
        if (remote && isNativeApp() && !afterLogin) {
          if (session) clearRemoteSession(remote.id)
          const login = await loginRemoteForSession(remote)
          if (login.ok) {
            await this.validateAndConnect(token, true)
            return
          }
          if (login.codeRequired) {
            this.setAuthError(login.error, 'code-required')
            return
          }
          // `legacy` means the server has no session endpoint at all, so the
          // refusal above really was about the token. Fall through.
        }
        // Invalid token — clear it and wait for the user to provide another.
        // Only the focused transport may do this: a satellite must not sign
        // the whole app out because one secondary instance refused it.
        if (!remote && this.isFocused) {
          localStorage.removeItem('jean-http-token')
        }
        this.setAuthError(
          token
            ? "That access token was refused. Check the token in Jean's Web Access settings."
            : "Enter the access token from Jean's Web Access settings.",
          token ? 'rejected' : 'signed-out'
        )
        return
      }

      // Native desktop UI is bundled with the client; warn (do not block)
      // when remote appVersion differs so users can still connect.
      if (remote && isNativeApp()) {
        try {
          const body = (await res.json()) as { appVersion?: string | null }
          warnRemoteVersionMismatch(body.appVersion)
        } catch {
          // Older servers or non-JSON auth bodies: allow connect.
        }
      }
    } catch {
      if (remote && this.isFocused) {
        this.setAuthError(
          "Jean could not reach the server's authentication endpoint. Check that the server is running and the URL and port are correct. If the address opens in a browser, update and restart the remote Jean server so it allows desktop connections (CORS).",
          'unreachable'
        )
        return
      }
      // The initial page load may race server startup, and a satellite's server
      // can go down at any time. Both retry: an unreachable server is not an
      // auth failure, and setting one here would stop the retry loop for good.
      this.setAuthError(null)
      this.scheduleConnectRetry()
      return
    }

    // The connection may have been deleted while the probe was in flight; its
    // transport is gone from the registry, so a socket opened now could never
    // be closed — and would resolve to the hub, not to the removed remote.
    if (this._disposed || !this._connectEnabled) return

    // Token valid (or not required) — clear any previous auth error and connect
    this.setAuthError(null)
    this.connectWs(token)
  }

  private connectWs(token: string): void {
    const base = new URL(backendUrlFor(this.remote, 'ws'))
    base.protocol = base.protocol === 'https:' ? 'wss:' : 'ws:'
    // Browsers refuse to attach custom headers to a WebSocket handshake, so a
    // native client's session has to travel in the query string here. It is
    // still a better thing to put there than the token: it expires, and it can
    // be revoked from the server without rotating anything.
    const session = remoteSessionFor(this.remote)
    if (session) {
      base.searchParams.set('session', session)
    } else {
      base.searchParams.set('token', token)
    }
    const url = base.toString()

    this.ws = new WebSocket(url)
    this.clearConnectWatchdog()
    this.connectWatchdog = setTimeout(() => {
      if (this.ws?.readyState === WebSocket.CONNECTING) {
        console.warn(
          '[WsTransport] WebSocket connect watchdog fired, retrying connection'
        )
        try {
          this.ws.close()
        } catch {
          // Ignore close errors; the initial-connect retry handles recovery.
        }
      }
    }, WsTransport.CONNECT_TIMEOUT)

    this.ws.onopen = () => {
      this.clearConnectWatchdog()
      this._lastInbound = Date.now()
      this.startLivenessTimer()
      this._hasConnectedOnce = true
      this.setConnected(true)
      // Do NOT clear the backoff here. The hub accepts the WebSocket upgrade
      // before it knows whether the remote is reachable, so a dead remote
      // produces open-then-immediately-close. Resetting on open would pin the
      // delay at 100ms forever and hammer the hub — and through it, the remote.
      // Only a connection that stayed up counts as proven.
      this.clearStabilityTimer()
      this.stabilityTimer = setTimeout(() => {
        this.stabilityTimer = null
        this.connectRetryAttempt = 0
      }, WsTransport.STABLE_CONNECTION_MS)

      // Flush queued messages
      for (const item of this.queue) {
        this.ws?.send(item.data)
        item.resolve()
      }
      this.queue = []
    }

    this.ws.onmessage = event => {
      this._lastInbound = Date.now()
      // Fast path: server app-level heartbeat is a fixed string every ~20s.
      // Skip JSON.parse on the idle hot path (browser cannot observe protocol
      // ping/pong, so these text frames are the liveness signal).
      if (event.data === '{"type":"heartbeat"}') {
        return
      }
      try {
        const msg: WsMessage = JSON.parse(event.data)
        this.handleMessage(msg)
      } catch {
        // Ignore malformed messages
      }
    }

    this.ws.onclose = () => {
      const wasConnected = this._connected

      // Only the transport that drove the app triggers the reload path. The
      // listeners live on the registry, not on this instance: App.tsx
      // subscribes during its first render, before the connection list has
      // loaded, when the focused id still reads as 'local'.
      if (wasConnected && this._drivesGlobalState) {
        for (const callback of establishedDisconnectListeners) {
          try {
            callback()
          } catch (error) {
            console.error(
              '[WsTransport] Established disconnect listener failed:',
              error
            )
          }
        }
      }

      this.clearConnectWatchdog()
      this.clearStabilityTimer()
      this.stopLivenessTimer()
      this.ws = null

      this.setConnected(false)
      if (wasConnected && this.remote && this.isFocused) {
        this.setAuthError(
          'Connection to the selected Jean server was lost.',
          'unreachable'
        )
      }

      // Clear event buffer — stale events from a dead connection
      // must not be delivered when the next connection opens.
      this.eventBuffer.clear()

      // Reject all pending command promises immediately — the server
      // response will never arrive on this socket. Prevents waiting
      // the full timeout (up to 10 min for long-running commands).
      for (const [, pending] of this.pending.entries()) {
        clearTimeout(pending.timeout)
        pending.reject(new Error('WebSocket disconnected'))
      }
      this.pending.clear()

      // Clear queued-but-unsent messages so a later page bootstrap cannot
      // spawn duplicate CLI processes.
      this.queue = []

      // Satellites always recover in place. The focused transport only retries
      // while it has never connected; once established it waits for the
      // app-level reload path above.
      if (!this.isFocused || (!wasConnected && !this._hasConnectedOnce)) {
        this.scheduleConnectRetry()
      }
    }

    this.ws.onerror = () => {
      // onclose will fire after onerror
    }
  }

  // Commands that spawn/attach to long-lived processes or are critical to
  // terminal lifecycle. These get an extended timeout instead of the default
  // 60s so idle connection edges do not falsely fail terminal sessions.
  private static readonly LONG_RUNNING_COMMANDS: ReadonlySet<string> = new Set([
    'send_chat_message',
    'run_review_with_ai',
    'create_pr_with_ai_content',
    'create_commit_with_ai',
    'execute_summarization',
    'install_claude_cli',
    'install_codex_cli',
    'install_opencode_cli',
    'install_pi_cli',
    'install_gh_cli',
    'install_coderabbit_cli',
    'update_coderabbit_cli',
    'run_coderabbit_review',
    'trigger_coderabbit_pr_review',
    'start_terminal',
    'terminal_write',
    'terminal_resize',
    'stop_terminal',
    'get_active_terminals',
    'has_active_terminal',
    'get_terminal_listening_ports',
  ])
  private static readonly LONG_TIMEOUT = 30 * 60_000
  private static readonly DEFAULT_TIMEOUT = 60_000
  private static readonly CONNECT_TIMEOUT = 12_000
  /** How long a socket must stay open before its backoff counter is cleared. */
  private static readonly STABLE_CONNECTION_MS = 10_000
  private static readonly MAX_QUEUE_SIZE = 500
  /** If no inbound traffic for this long, assume connection is dead.
   *  Must exceed the server's app-level heartbeat interval (20s); protocol
   *  ping/pong alone is not visible to browser JavaScript. */
  private static readonly INBOUND_TIMEOUT = 50_000
  private static readonly LIVENESS_CHECK_INTERVAL = 10_000

  /** Call a backend command over WebSocket. */
  async invoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
    const id = generateId()
    const data = JSON.stringify({
      type: 'invoke',
      id,
      command,
      args: args || {},
    })

    const timeoutMs = WsTransport.LONG_RUNNING_COMMANDS.has(command)
      ? WsTransport.LONG_TIMEOUT
      : WsTransport.DEFAULT_TIMEOUT

    return new Promise<T>((resolve, reject) => {
      if (this._authError) {
        reject(new Error(this._authError))
        return
      }

      const timeout = setTimeout(() => {
        this.pending.delete(id)
        reject(
          new Error(`Command '${command}' timed out after ${timeoutMs / 1000}s`)
        )
      }, timeoutMs)

      this.pending.set(id, {
        resolve: resolve as (data: unknown) => void,
        reject,
        timeout,
      })

      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(data)
      } else {
        if (this.queue.length >= WsTransport.MAX_QUEUE_SIZE) {
          clearTimeout(timeout)
          this.pending.delete(id)
          reject(
            new Error(
              `Command queue is full (${WsTransport.MAX_QUEUE_SIZE}). Restarting connection...`
            )
          )
          this.restartConnectionAttempt()
          return
        }

        // Queue for when connection is established
        this.queue.push({
          data,
          resolve() {
            /* noop */
          },
        })
        this.connect()
      }
    })
  }

  /** Request buffered terminal output after a full page refresh. */
  requestTerminalReplay(terminalId: string, lastSeq = 0): void {
    const currentLastSeq = this._lastSeqByTerminal.get(terminalId)
    const effectiveLastSeq =
      currentLastSeq == null ? lastSeq : Math.max(lastSeq, currentLastSeq)
    this._lastSeqByTerminal.set(terminalId, effectiveLastSeq)

    const payload = JSON.stringify({
      type: 'terminal_replay',
      terminal_id: terminalId,
      last_seq: effectiveLastSeq,
    })

    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(payload)
      return
    }

    if (this._connectEnabled) {
      this.connect()
    }
  }

  /** Register an event listener. Returns an unlisten function. */
  listen<T>(
    event: string,
    handler: (event: { payload: T }) => void
  ): () => void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set())
    }
    const typedHandler = handler as (event: { payload: unknown }) => void
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    this.listeners.get(event)!.add(typedHandler)

    // Drain buffered events that arrived before this listener was registered
    // (covers the gap between WS onopen and React effect listener setup)
    const buffered = this.eventBuffer.get(event)
    if (buffered && buffered.length > 0) {
      this.eventBuffer.delete(event)
      const now = Date.now()
      for (const { msg, bufferedAt } of buffered) {
        if (now - bufferedAt > WsTransport.EVENT_BUFFER_MAX_AGE) continue
        try {
          typedHandler({ payload: msg.payload })
        } catch (e) {
          console.error(`[WsTransport] Error draining buffered '${event}':`, e)
        }
      }
    }

    // Ensure connected once bootstrap explicitly enables it
    if (this._connectEnabled) {
      this.connect()
    }

    return () => {
      this.listeners.get(event)?.delete(typedHandler)
      if (this.listeners.get(event)?.size === 0) {
        this.listeners.delete(event)
      }
    }
  }

  private handleMessage(msg: WsMessage): void {
    if (msg.type === 'heartbeat') {
      // onmessage already refreshed _lastInbound. No listener dispatch.
      return
    }

    if (msg.type === 'response' && msg.id) {
      const pending = this.pending.get(msg.id)
      if (pending) {
        clearTimeout(pending.timeout)
        this.pending.delete(msg.id)
        pending.resolve(msg.data)
      }
    } else if (msg.type === 'error' && msg.id) {
      const pending = this.pending.get(msg.id)
      if (pending) {
        clearTimeout(pending.timeout)
        this.pending.delete(msg.id)
        pending.reject(new Error(msg.error || 'Unknown error'))
      }
    } else if (msg.type === 'event' && msg.event) {
      // A satellite subscribes to a couple of list-level events, but the server
      // broadcasts everything to every client. Drop what nobody is listening
      // for instead of buffering it: replay dedup and the listener-gap buffer
      // only matter for the transport that drives the app, and unbounded
      // per-session sequence tracking on a firehose is pure leak.
      if (!this.isFocused) {
        const satelliteHandlers = this.listeners.get(msg.event)
        if (!satelliteHandlers?.size) return
        for (const handler of satelliteHandlers) {
          try {
            handler({ payload: msg.payload })
          } catch (e) {
            console.error(`[WsTransport] Error in '${msg.event}' handler:`, e)
          }
        }
        return
      }

      // Track sequence numbers for bootstrap/live overlap deduplication.
      if (msg.seq != null && msg.payload) {
        const payload = msg.payload as Record<string, unknown>
        const sessionId = payload.session_id as string | undefined
        if (sessionId) {
          const lastSeen = this._lastSeqBySession.get(sessionId)
          if (lastSeen != null && msg.seq <= lastSeen) {
            return // Already processed — skip duplicate from replay
          }
          this._lastSeqBySession.set(sessionId, msg.seq)
          if (msg.event === 'chat:done' || msg.event === 'chat:cancelled') {
            this._lastSeqBySession.delete(sessionId)
          }
        }

        // Track terminal sequence numbers for explicit full-refresh replay.
        const terminalId = payload.terminal_id as string | undefined
        if (terminalId && msg.event.startsWith('terminal:')) {
          const lastSeen = this._lastSeqByTerminal.get(terminalId)
          if (lastSeen != null && msg.seq <= lastSeen) {
            return // Duplicate from replay — skip
          }
          this._lastSeqByTerminal.set(terminalId, msg.seq)
          if (msg.event === 'terminal:stopped') {
            this._lastSeqByTerminal.delete(terminalId)
          }
        }
      }

      const handlers = this.listeners.get(msg.event)
      if (handlers && handlers.size > 0) {
        for (const handler of handlers) {
          try {
            handler({ payload: msg.payload })
          } catch (e) {
            console.error(`[WsTransport] Error in '${msg.event}' handler:`, e)
          }
        }
      } else {
        // Buffer events that arrive before listeners are registered
        // (happens during the React render cycle gap after WS connects)
        const buffered = this.eventBuffer.get(msg.event) ?? []
        if (buffered.length < WsTransport.EVENT_BUFFER_MAX_SIZE) {
          buffered.push({ msg, bufferedAt: Date.now() })
          this.eventBuffer.set(msg.event, buffered)
        }
      }
    }
  }

  private scheduleConnectRetry(): void {
    if (this.connectRetryTimer) return
    // The focused transport only retries before its first connection; after
    // that the app reloads instead. Satellites keep retrying indefinitely so
    // an instance that comes back online rejoins the aggregated view on its own.
    if (this._hasConnectedOnce && this.isFocused) return
    // Don't retry if there's an auth error — user needs to fix the token.
    if (this._authError) return

    // Exponential backoff while establishing the initial connection.
    const delay =
      this.connectRetryAttempt === 0
        ? 100
        : Math.min(500 * 2 ** (this.connectRetryAttempt - 1), 30_000)
    this.connectRetryAttempt++

    this.connectRetryTimer = setTimeout(() => {
      this.connectRetryTimer = null
      this.connect()
    }, delay)
  }

  private clearConnectWatchdog(): void {
    if (!this.connectWatchdog) return
    clearTimeout(this.connectWatchdog)
    this.connectWatchdog = null
  }

  private clearStabilityTimer(): void {
    if (!this.stabilityTimer) return
    clearTimeout(this.stabilityTimer)
    this.stabilityTimer = null
  }

  private startLivenessTimer(): void {
    this.stopLivenessTimer()
    this.livenessTimer = setInterval(() => {
      if (this.ws?.readyState !== WebSocket.OPEN) return
      if (Date.now() - this._lastInbound > WsTransport.INBOUND_TIMEOUT) {
        console.warn(
          '[WsTransport] No inbound traffic, closing stale connection for reload'
        )
        try {
          this.ws.close()
        } catch {
          // Ignore close errors; a successful close triggers the app reload.
        }
      }
    }, WsTransport.LIVENESS_CHECK_INTERVAL)
  }

  private stopLivenessTimer(): void {
    if (!this.livenessTimer) return
    clearInterval(this.livenessTimer)
    this.livenessTimer = null
  }

  /** Re-check the connection when the page returns to the foreground or the
   *  network comes back. Fires on visibilitychange / online / pageshow. */
  private handleWake = (): void => {
    if (!this._connectEnabled) return
    // visibilitychange also fires on hide — only act when the page is visible.
    if (typeof document !== 'undefined' && document.hidden) return

    const state = this.ws?.readyState
    if (state === WebSocket.CONNECTING) return // connectWatchdog covers this

    if (state === WebSocket.OPEN) {
      // Socket claims to be open. After a suspend it may be a zombie, but a
      // recent socket may simply have queued frames. Replace one already past
      // the liveness timeout immediately so iOS resume adds no extra delay.
      if (Date.now() - this._lastInbound > WsTransport.INBOUND_TIMEOUT) {
        console.warn('[WsTransport] Stale socket after resume, reloading app')
        try {
          this.ws?.close()
        } catch {
          // Ignore close errors; a successful close triggers the app reload.
        }
      }
      return
    }

    // Before the first successful connection, retry immediately on wake.
    // Satellites also retry on wake after a drop; the focused transport does
    // not, because an established drop reloads the app instead.
    if (this._hasConnectedOnce && this.isFocused) return
    if (this.connectRetryTimer) {
      clearTimeout(this.connectRetryTimer)
      this.connectRetryTimer = null
    }
    this.connectRetryAttempt = 0
    this.connect()
  }

  private restartConnectionAttempt(): void {
    this.clearConnectWatchdog()
    if (this.ws) {
      try {
        this.ws.close()
      } catch {
        // Ignore close errors; initial connection retry will recover.
      }
      return
    }
    this.scheduleConnectRetry()
  }

  ingestBootstrapEvents(events: BootstrapEvent[]): void {
    const sorted = [...events].sort(
      (a, b) =>
        (a.seq ?? Number.MAX_SAFE_INTEGER) - (b.seq ?? Number.MAX_SAFE_INTEGER)
    )
    for (const event of sorted) {
      this.handleMessage(event)
    }
  }
}

// ---------------------------------------------------------------------------
// Transport registry (one WebSocket per Jean instance)
// ---------------------------------------------------------------------------

/**
 * One transport per instance id. The FOCUSED instance is whatever
 * {@link getActiveConnectionId} returns — focus is derived, never stored here,
 * so selecting another connection re-points the bare `invoke()`/`listen()`
 * helpers without any bookkeeping. Every other live transport is a SATELLITE:
 * a background reader used for the aggregated session list.
 */
const transports = new Map<string, WsTransport>()
const registrySubscribers = new Set<() => void>()
/**
 * App-level "the connection I was using just dropped" callbacks.
 *
 * Registry-scoped on purpose: subscribers register at first render, while the
 * connection list is still loading and the focused id has not resolved yet, so
 * binding them to a particular transport would attach them to the wrong one.
 */
const establishedDisconnectListeners = new Set<() => void>()
let registryVersion = 0

function notifyTransportRegistry(): void {
  registryVersion++
  for (const cb of registrySubscribers) cb()
}

/**
 * Monotonic counter bumped on every transport state change. A number is a
 * stable `useSyncExternalStore` snapshot; the statuses themselves are derived
 * from it, which a freshly-built array could not be.
 */
export function getTransportRegistryVersion(): number {
  return registryVersion
}

/** Subscribe to any transport's state change (connection, auth, focus). */
export function subscribeToTransports(callback: () => void): () => void {
  registrySubscribers.add(callback)
  return () => {
    registrySubscribers.delete(callback)
  }
}

/** Get (creating if needed) the transport for an instance. */
export function getTransport(instanceId: string): WsTransport {
  const existing = transports.get(instanceId)
  if (existing) return existing
  const created = new WsTransport(instanceId)
  transports.set(instanceId, created)
  return created
}

/** Look up a transport without creating one — safe to call during render. */
function peekTransport(instanceId: string): WsTransport | undefined {
  return transports.get(instanceId)
}

function focusedTransport(): WsTransport {
  return getTransport(getActiveConnectionId())
}

/** Drop a transport whose connection was deleted, closing its socket. */
export function releaseTransport(instanceId: string): void {
  const transport = transports.get(instanceId)
  if (!transport) return
  transports.delete(instanceId)
  transport.dispose()
  notifyTransportRegistry()
}

/** Ids of every instance with a live transport (focused included). */
export function getLiveTransportIds(): string[] {
  return [...transports.keys()]
}

export type InstanceStatus =
  | 'idle'
  | 'connecting'
  | 'connected'
  | 'offline'
  | 'auth-error'

/** Current status of an instance; 'idle' when no transport exists yet. */
export function getInstanceStatus(instanceId: string): InstanceStatus {
  if (isNativeApp() && instanceId === LOCAL_CONNECTION_ID) return 'connected'
  return peekTransport(instanceId)?.status ?? 'idle'
}

/**
 * Open (or reuse) a background transport for an instance that is not focused.
 * No-op in native mode for the local instance, which talks over Tauri IPC.
 */
export function ensureSatelliteTransport(instanceId: string): void {
  if (isE2eMocked) return
  if (isNativeApp() && instanceId === LOCAL_CONNECTION_ID) return
  getTransport(instanceId).enableConnect()
}

/** True when this instance is reached through the local Tauri IPC bridge. */
function usesNativeIpc(instanceId: string): boolean {
  return isNativeApp() && instanceId === LOCAL_CONNECTION_ID
}

/**
 * Call a command on a specific instance. The focused instance goes through the
 * normal {@link invoke} path (native IPC, editor remapping, E2E mocks);
 * satellites go straight to their own WebSocket.
 */
export async function invokeOn<T>(
  instanceId: string,
  command: string,
  args?: Record<string, unknown>
): Promise<T> {
  if (instanceId === getActiveConnectionId()) return invoke<T>(command, args)
  if (usesNativeIpc(instanceId)) {
    const { invoke: tauriInvoke } = await import('@tauri-apps/api/core')
    return tauriInvoke<T>('dispatch_core_command', {
      command,
      args: args ?? {},
    })
  }
  return getTransport(instanceId).invoke<T>(command, args)
}

/**
 * Listen for an event on a specific instance. Satellite handlers receive the
 * originating instance id so callers can never mix two instances' payloads.
 */
export async function listenOn<T>(
  instanceId: string,
  event: string,
  handler: (event: { payload: T; instanceId: string }) => void
): Promise<() => void> {
  if (instanceId === getActiveConnectionId() || usesNativeIpc(instanceId)) {
    return listen<T>(event, payload => handler({ ...payload, instanceId }))
  }
  return getTransport(instanceId).listen<T>(event, payload =>
    handler({ ...payload, instanceId })
  )
}

// ---------------------------------------------------------------------------
// React hooks for connection status (browser mode only)
// ---------------------------------------------------------------------------

const subscribe = (cb: () => void) => subscribeToTransports(cb)
const getSnapshot = () =>
  peekTransport(getActiveConnectionId())?.getSnapshot() ?? false
const getAuthErrorSnapshot = () =>
  peekTransport(getActiveConnectionId())?.getAuthErrorSnapshot() ?? null
const getAuthReasonSnapshot = () =>
  peekTransport(getActiveConnectionId())?.getAuthReasonSnapshot() ?? null

// E2E mock: always report connected, no auth errors
const isE2eMocked =
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  typeof window !== 'undefined' && !!(window as any).__JEAN_E2E_MOCK__
// eslint-disable-next-line @typescript-eslint/no-empty-function
const noopSubscribe = () => () => {}

/**
 * React hook that returns the current WebSocket connection status.
 * Only meaningful in browser mode (!isNativeApp()).
 */
export function useWsConnectionStatus(): boolean {
  return useSyncExternalStore(
    isE2eMocked ? noopSubscribe : subscribe,
    isE2eMocked ? () => true : getSnapshot
  )
}

/** Start browser WebSocket transport after preload/bootstrap is complete. */
export function connectTransport(): void {
  if (!usesWebSocketBackend() || isE2eMocked) return
  setWebAccessEnabled(true)
  focusedTransport().enableConnect()
}

/** Run immediately when the established browser WebSocket in use disconnects. */
export function onEstablishedWsDisconnect(callback: () => void): () => void {
  establishedDisconnectListeners.add(callback)
  return () => {
    establishedDisconnectListeners.delete(callback)
  }
}

/**
 * Imperative connection check for non-React paths (e.g. xterm onData handler).
 * Native Tauri / E2E mock: always true (no transport drop concept).
 * Web mode: reflects current WebSocket connected state.
 */
export function isTransportConnected(): boolean {
  if (!usesWebSocketBackend() || isE2eMocked) return true
  return focusedTransport().connected
}

/** Feed replayed server events through the normal event pipeline before connect. */
export function ingestBootstrapEvents(events: BootstrapEvent[]): void {
  if (events.length === 0) return
  focusedTransport().ingestBootstrapEvents(events)
}

/**
 * React hook that returns the current auth error message, or null if none.
 * Only meaningful in browser mode (!isNativeApp()).
 */
export function useWsAuthError(): string | null {
  return useSyncExternalStore(
    isE2eMocked ? noopSubscribe : subscribe,
    isE2eMocked ? () => null : getAuthErrorSnapshot
  )
}

/**
 * React hook that returns why authentication is pending, or null when the
 * session is authenticated. Lets the UI tell a first visit apart from a
 * refused token instead of reporting both as a connection failure.
 */
export function useWsAuthReason(): WsAuthReason | null {
  return useSyncExternalStore(
    isE2eMocked ? noopSubscribe : subscribe,
    isE2eMocked ? () => null : getAuthReasonSnapshot
  )
}

/**
 * Forget the access token stored in this browser and return to the sign-in
 * screen. Only affects this device — the server keeps running and other
 * browsers stay signed in.
 */
export function signOutOfWebAccess(): void {
  localStorage.removeItem('jean-http-token')
  // Reload on a bare origin. A bookmarked `?token=...` takes priority over
  // localStorage on boot, so keeping the current URL would sign us straight
  // back in and make the button look broken.
  const leave = () => window.location.replace(`${window.location.origin}/`)
  // Also clear the server-side session cookie, then leave regardless of the
  // result (older servers without /api/logout must not block sign-out).
  fetch(`${window.location.origin}/api/logout`, {
    method: 'POST',
    credentials: 'same-origin',
  }).then(leave, leave)
}
