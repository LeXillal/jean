import { useEffect, useState, type FormEvent } from 'react'
import { ServerOff, ShieldCheck } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  submitRemoteTwoFactorCode,
  type WsAuthReason,
} from '@/lib/transport'
import {
  LOCAL_CONNECTION_ID,
  markConnectionSwitch,
  selectConnection,
  type RemoteConnection,
} from '@/lib/remote-connections'
import { dismissTransientUi } from '@/lib/dismiss-transient-ui'

function reloadPage() {
  window.location.reload()
}

export function RemoteConnectionRecovery({
  connection,
  error,
  reason,
}: {
  connection: RemoteConnection
  error: string
  reason?: WsAuthReason | null
}) {
  // The token was accepted and the server is waiting for a code: this is a
  // sign-in step, not a failure, and it needs its own surface.
  const codeRequired = reason === 'code-required'
  const [code, setCode] = useState('')
  const [codeError, setCodeError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  // Drop open context menus / settings / dialogs so they cannot sit above
  // this surface or leave body pointer-events locked (issue #623).
  useEffect(() => {
    dismissTransientUi()
  }, [])

  useEffect(() => {
    // Never reload under a half-typed code — the retry loop exists for a server
    // that is down, and a server asking for a code is very much up.
    if (codeRequired) return
    const retryTimer = window.setInterval(reloadPage, 10_000)
    return () => window.clearInterval(retryTimer)
  }, [codeRequired])

  const handleCodeSubmit = (event: FormEvent) => {
    event.preventDefault()
    const trimmed = code.trim()
    if (!trimmed) return
    setSubmitting(true)
    setCodeError(null)
    void submitRemoteTwoFactorCode(connection, trimmed).then(result => {
      if (result.ok) return // the page is reloading
      setSubmitting(false)
      setCode('')
      setCodeError(result.error)
    })
  }

  if (codeRequired) {
    return (
      <div className="fixed inset-x-0 bottom-0 top-8 z-[100] flex items-center justify-center bg-background">
        <div className="mx-4 w-full max-w-md rounded-lg border bg-card p-6 shadow-lg">
          <div className="flex items-center gap-2">
            <ShieldCheck className="size-5 text-muted-foreground" />
            <h2 className="font-semibold">Two-factor authentication</h2>
          </div>
          <p className="mt-2 text-sm text-muted-foreground">
            Enter the current code from your authenticator app to sign in to{' '}
            {connection.name}.
          </p>
          <form className="mt-5 space-y-2" onSubmit={handleCodeSubmit}>
            <Label htmlFor="remote-2fa-code">Authentication code</Label>
            <Input
              id="remote-2fa-code"
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
              aria-describedby={codeError ? 'remote-2fa-error' : undefined}
              aria-invalid={!!codeError}
            />
            {codeError && (
              <p
                id="remote-2fa-error"
                role="alert"
                className="text-xs text-destructive"
              >
                {codeError}
              </p>
            )}
            <div className="flex flex-wrap gap-2 pt-3">
              <Button type="submit" disabled={submitting || !code.trim()}>
                {submitting ? 'Verifying…' : 'Verify'}
              </Button>
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  markConnectionSwitch()
                  selectConnection(LOCAL_CONNECTION_ID)
                  reloadPage()
                }}
              >
                Switch to Local
              </Button>
            </div>
          </form>
        </div>
      </div>
    )
  }

  return (
    // z-[100] sits above dialogs (70) and menus/popovers (80).
    <div className="fixed inset-x-0 bottom-0 top-8 z-[100] flex items-center justify-center bg-background">
      <div className="mx-4 w-full max-w-md rounded-lg border bg-card p-6 shadow-lg">
        <div className="flex items-center gap-2">
          <ServerOff className="size-5 text-destructive" />
          <h2 className="font-semibold">
            Couldn&apos;t connect to {connection.name}
          </h2>
        </div>
        <p className="mt-2 text-sm text-muted-foreground">{error}</p>
        <p className="mt-1 truncate text-xs text-muted-foreground">
          {connection.url}
        </p>
        <div className="mt-5 flex flex-wrap gap-2">
          <Button onClick={reloadPage}>Retry</Button>
          <Button
            variant="outline"
            onClick={() =>
              window.dispatchEvent(
                new CustomEvent('open-remote-connections', {
                  detail: { id: connection.id },
                })
              )
            }
          >
            Edit connection
          </Button>
          <Button
            variant="ghost"
            onClick={() => {
              markConnectionSwitch()
              selectConnection(LOCAL_CONNECTION_ID)
              reloadPage()
            }}
          >
            Switch to Local
          </Button>
        </div>
      </div>
    </div>
  )
}
