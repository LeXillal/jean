import { useState, type FormEvent } from 'react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import type { WsAuthReason } from '@/lib/transport'
import { webAccessServerLabel } from '@/lib/environment'

/** What the server said about a submitted token/code pair. */
export type SignInResult =
  | { ok: true }
  | { ok: false; codeRequired: boolean; error: string }

interface WebAccessAuthScreenProps {
  authError: string
  /** Why we are asking. Defaults to a first visit rather than a failure.
   * Whatever the reason, the form stays available: submitting a token
   * reloads the page, which is also how a lost connection recovers. */
  reason?: Exclude<WsAuthReason, 'unreachable'>
  /**
   * Resolves only when sign-in was refused: success reloads the page. May
   * return nothing, for callers that handle the outcome themselves.
   */
  onTokenSubmit: (
    token: string,
    code?: string
  ) => Promise<SignInResult> | undefined
}

export function WebAccessAuthScreen({
  authError,
  reason = 'signed-out',
  onTokenSubmit,
}: WebAccessAuthScreenProps) {
  const [token, setToken] = useState('')
  const [code, setCode] = useState('')
  // The server only asks for a code once the token has checked out, so this
  // never reveals whether 2FA is on to someone guessing tokens.
  const [codeRequired, setCodeRequired] = useState(false)
  const [codeError, setCodeError] = useState<string | null>(null)
  // A refusal that came back from this form's own submission, as opposed to
  // the `authError` prop describing whatever failed before the page loaded.
  const [tokenError, setTokenError] = useState<string | null>(null)
  const [emptyError, setEmptyError] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  // The refused-token message describes the previous submission; drop it as
  // soon as the user starts editing a replacement.
  const [edited, setEdited] = useState(false)

  const host = webAccessServerLabel()
  const fieldError = emptyError
    ? "Enter the access token from Jean's Web Access settings."
    : (tokenError ??
      (reason === 'rejected' && !edited ? authError : null))

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    const trimmed = token.trim()
    if (!trimmed) {
      setEmptyError(true)
      return
    }
    setEmptyError(false)
    setCodeError(null)
    setTokenError(null)
    // A successful sign-in reloads the page (validation happens on the fresh
    // load), so the button is only ever re-enabled when we get an answer back —
    // which only happens on refusal.
    setSubmitting(true)
    const result = onTokenSubmit(trimmed, codeRequired ? code.trim() : undefined)
    if (!result) return
    void result.then(outcome => {
      if (outcome.ok) return
      setSubmitting(false)
      if (outcome.codeRequired) {
        setCodeRequired(true)
        // Only an actual attempt deserves an error; the first prompt is not a
        // failure, it is the second step.
        setCodeError(code.trim() ? outcome.error : null)
        setCode('')
        return
      }
      // Back to step one: the token itself was refused, so a code field would
      // be asking for the answer to a question that no longer applies.
      setCodeRequired(false)
      setCodeError(null)
      setTokenError(outcome.error)
    })
  }

  return (
    <div className="w-full max-w-sm px-6">
      <div className="flex flex-col items-center text-center">
        <img
          src="/logo.png"
          alt=""
          width={48}
          height={48}
          className="size-12 rounded-xl"
        />
        <h1 className="mt-5 text-xl font-semibold tracking-tight">
          Sign in to Jean
        </h1>
        {host && (
          <p className="mt-1.5 font-mono text-xs text-muted-foreground">
            {host}
          </p>
        )}
      </div>

      <form className="mt-8 space-y-4" onSubmit={handleSubmit}>
        <div className="space-y-2">
          <Label htmlFor="web-access-token">Access token</Label>
          <Input
            id="web-access-token"
            type="password"
            autoComplete="current-password"
            autoFocus
            value={token}
            onChange={event => {
              setToken(event.target.value)
              if (emptyError) setEmptyError(false)
              if (tokenError) setTokenError(null)
              if (!edited) setEdited(true)
            }}
            placeholder="Paste your Jean access token"
            aria-describedby={fieldError ? 'web-access-token-error' : undefined}
            aria-invalid={!!fieldError}
          />
          {fieldError && (
            <p
              id="web-access-token-error"
              role="alert"
              className="text-xs text-destructive"
            >
              {fieldError}
            </p>
          )}
        </div>

        {codeRequired && (
          <div className="space-y-2">
            <Label htmlFor="web-access-code">Authentication code</Label>
            <Input
              id="web-access-code"
              // `one-time-code` is what lets phones offer the code from the
              // notification, and `numeric` brings up the right keypad.
              autoComplete="one-time-code"
              inputMode="numeric"
              pattern="[0-9]*"
              maxLength={6}
              autoFocus
              value={code}
              onChange={event => {
                setCode(event.target.value)
                if (codeError) setCodeError(null)
              }}
              placeholder="6-digit code"
              aria-describedby={codeError ? 'web-access-code-error' : undefined}
              aria-invalid={!!codeError}
            />
            {codeError ? (
              <p
                id="web-access-code-error"
                role="alert"
                className="text-xs text-destructive"
              >
                {codeError}
              </p>
            ) : (
              <p className="text-xs text-muted-foreground">
                Open your authenticator app and enter the current code.
              </p>
            )}
          </div>
        )}

        <Button type="submit" className="w-full" disabled={submitting}>
          {submitting ? 'Signing in…' : codeRequired ? 'Verify' : 'Sign in'}
        </Button>
      </form>

      <p className="mt-8 text-center text-xs text-muted-foreground">
        Find the token in Jean&apos;s Web Access settings.
      </p>
    </div>
  )
}
