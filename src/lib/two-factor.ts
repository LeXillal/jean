/**
 * Client for the server's second-factor endpoints (`/api/2fa/*`).
 *
 * These are plain HTTP rather than Tauri commands on purpose: 2FA guards a
 * server's *web* access, and the state lives inside the running HTTP server.
 * Talking to it over HTTP means the browser, the desktop app configuring its
 * own local server, and a client pointed at a remote all drive the same code
 * path — and there is no second copy of the state to keep in sync.
 */

import { isNativeApp } from './environment'

export interface TwoFactorStatus {
  enabled: boolean
  /**
   * Enrolled, but this client cannot manage it yet: the desktop app was
   * authenticating with the raw token, which a server with a second factor no
   * longer accepts. A code unlocks it (see `unlockTwoFactor`).
   */
  locked?: boolean
}

export interface EnrollmentSecret {
  secret: string
  otpauth_url: string
}

/** Where to reach the server, and what proves who we are. */
export interface TwoFactorTarget {
  /** Server base URL. Omitted in web mode, where the page origin is the server. */
  url?: string | null
  /** Raw token, needed only when no session cookie applies (desktop → local). */
  token?: string | null
}

/**
 * Session held by the desktop app for the server it is configuring.
 *
 * The browser needs no equivalent: its `HttpOnly` cookie already survives 2FA
 * being switched on. The desktop app has no cookie for the local server, and
 * enabling 2FA is precisely the moment its token stops working — so it takes a
 * session while the token still opens doors, and keeps using that.
 */
let nativeSession: string | null = null

function endpoint(target: TwoFactorTarget, path: string): string {
  const base = isNativeApp() && target.url ? target.url : window.location.origin
  const url = new URL(path, `${base.replace(/\/+$/, '')}/`)
  // In the browser the HttpOnly cookie authorizes and the token is not even
  // available to JavaScript; the desktop app has no cookie for the local
  // server, so it falls back to the token it just read from settings.
  if (isNativeApp() && !nativeSession && target.token) {
    url.searchParams.set('token', target.token)
  }
  return url.toString()
}

async function request<T>(
  target: TwoFactorTarget,
  path: string,
  init?: RequestInit
): Promise<T> {
  const res = await fetch(endpoint(target, path), {
    credentials: 'same-origin',
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(nativeSession ? { 'X-Jean-Session': nativeSession } : {}),
      ...init?.headers,
    },
  })
  const body = (await res.json().catch(() => null)) as
    | (T & { error?: string })
    | null
  if (!res.ok) {
    throw new Error(body?.error ?? `Request failed (${res.status})`)
  }
  if (!body) throw new Error('Server returned an unreadable response')
  return body
}

/**
 * Trade the token (and a code, when the server insists) for a session the
 * desktop app can keep using. No-op in the browser, which has its cookie.
 */
async function nativeLogin(
  target: TwoFactorTarget,
  code?: string
): Promise<'ok' | 'code-required' | 'failed'> {
  if (!isNativeApp() || !target.token) return 'failed'
  const url = new URL(
    'api/login',
    `${(target.url ?? window.location.origin).replace(/\/+$/, '')}/`
  ).toString()
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ token: target.token, code, transport: 'header' }),
  }).catch(() => null)
  if (!res) return 'failed'

  const body = (await res.json().catch(() => null)) as {
    session?: string
    code_required?: boolean
  } | null
  if (res.ok && body?.session) {
    nativeSession = body.session
    return 'ok'
  }
  return body?.code_required ? 'code-required' : 'failed'
}

/**
 * Take a session before enrolling, while the raw token still works.
 *
 * Without this the desktop app would enable 2FA and immediately lose the
 * ability to manage it, because the credential it was using stops being
 * accepted the moment the secret is confirmed.
 */
export async function prepareNativeSession(
  target: TwoFactorTarget
): Promise<void> {
  if (!isNativeApp() || nativeSession) return
  // Best effort: an older server has no `/api/login`, and it also has no
  // second factor to lock us out of.
  await nativeLogin(target)
}

export async function fetchTwoFactorStatus(
  target: TwoFactorTarget
): Promise<TwoFactorStatus> {
  try {
    return await request<TwoFactorStatus>(target, 'api/2fa')
  } catch (error) {
    // A desktop client refused here is the expected shape of "2FA got enabled
    // and my token no longer counts". Find out by logging in, which is also how
    // we get a credential that keeps working.
    if (!isNativeApp()) throw error
    const login = await nativeLogin(target)
    if (login === 'ok') return request<TwoFactorStatus>(target, 'api/2fa')
    if (login === 'code-required') return { enabled: true, locked: true }
    throw error
  }
}

/**
 * Authenticate the desktop app against a server whose second factor is already
 * on, so it can manage it. The code is verified but not spent for the caller's
 * purposes: turning 2FA off checks the code without consuming a step, so the
 * same one works for both halves of the flow.
 */
export async function unlockTwoFactor(
  target: TwoFactorTarget,
  code: string
): Promise<void> {
  const login = await nativeLogin(target, code)
  if (login !== 'ok') throw new Error('That code did not match.')
}

/**
 * Ask for a secret to enroll. Nothing is enforced until `confirmTwoFactor`
 * proves the authenticator app produces matching codes.
 */
export function beginTwoFactorEnrollment(
  target: TwoFactorTarget
): Promise<EnrollmentSecret> {
  return request<EnrollmentSecret>(target, 'api/2fa/enroll', { method: 'POST' })
}

export function confirmTwoFactor(
  target: TwoFactorTarget,
  code: string
): Promise<{ ok: boolean }> {
  return request(target, 'api/2fa/confirm', {
    method: 'POST',
    body: JSON.stringify({ code }),
  })
}

export function disableTwoFactor(
  target: TwoFactorTarget,
  code: string
): Promise<{ ok: boolean }> {
  return request(target, 'api/2fa/disable', {
    method: 'POST',
    body: JSON.stringify({ code }),
  })
}
