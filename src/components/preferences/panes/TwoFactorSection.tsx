import React, { useCallback, useEffect, useState } from 'react'
import QRCode from 'qrcode'
import { ShieldCheck, ShieldOff } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { toast } from 'sonner'
import { copyToClipboard } from '@/lib/clipboard'
import {
  beginTwoFactorEnrollment,
  confirmTwoFactor,
  disableTwoFactor,
  fetchTwoFactorStatus,
  prepareNativeSession,
  unlockTwoFactor,
  type EnrollmentSecret,
  type TwoFactorTarget,
} from '@/lib/two-factor'
import { SettingsSection } from '../SettingsSection'

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

/**
 * Enroll or remove the second factor guarding this server's web access.
 *
 * Only rendered while the server is running: the state lives in the server
 * process, and offering the controls against a stopped server would silently
 * do nothing.
 */
export const TwoFactorSection: React.FC<{ target: TwoFactorTarget }> = ({
  target,
}) => {
  const [enabled, setEnabled] = useState<boolean | null>(null)
  // Enrolled, but this client still has to prove itself with a code before it
  // can manage the factor.
  const [locked, setLocked] = useState(false)
  const [enrollment, setEnrollment] = useState<EnrollmentSecret | null>(null)
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [disarming, setDisarming] = useState(false)

  const targetUrl = target.url
  const targetToken = target.token

  const refresh = useCallback(async () => {
    try {
      const status = await fetchTwoFactorStatus({
        url: targetUrl,
        token: targetToken,
      })
      setEnabled(status.enabled)
      setLocked(status.locked === true)
    } catch {
      // An older server has no such endpoint; leave the section quiet rather
      // than showing a scary error for a feature it simply does not have.
      setEnabled(null)
    }
  }, [targetUrl, targetToken])

  useEffect(() => {
    void refresh()
  }, [refresh])

  // Render the QR whenever a new secret is issued. Drawn client-side so the
  // secret never becomes an image URL the server (or a proxy) could log.
  useEffect(() => {
    if (!enrollment) {
      setQrDataUrl(null)
      return
    }
    let cancelled = false
    void QRCode.toDataURL(enrollment.otpauth_url, { margin: 1, width: 200 })
      .then(url => {
        if (!cancelled) setQrDataUrl(url)
      })
      .catch(() => {
        // Falling back to the typed secret below is a complete path, not a
        // degraded one — every authenticator app accepts manual entry.
        if (!cancelled) setQrDataUrl(null)
      })
    return () => {
      cancelled = true
    }
  }, [enrollment])

  const handleEnroll = useCallback(async () => {
    setBusy(true)
    try {
      // Grab a session while the token is still accepted — after confirmation
      // it will not be.
      await prepareNativeSession({ url: targetUrl, token: targetToken })
      const secret = await beginTwoFactorEnrollment({
        url: targetUrl,
        token: targetToken,
      })
      setEnrollment(secret)
      setCode('')
    } catch (error) {
      toast.error(`Could not start enrollment: ${getErrorMessage(error)}`)
    } finally {
      setBusy(false)
    }
  }, [targetUrl, targetToken])

  const handleConfirm = useCallback(async () => {
    setBusy(true)
    try {
      await confirmTwoFactor({ url: targetUrl, token: targetToken }, code.trim())
      setEnrollment(null)
      setCode('')
      setEnabled(true)
      toast.success(
        'Two-factor authentication enabled. Signing in now needs a code — other devices holding only the token will be signed out.'
      )
    } catch (error) {
      toast.error(getErrorMessage(error))
    } finally {
      setBusy(false)
    }
  }, [targetUrl, targetToken, code])

  const handleDisable = useCallback(async () => {
    setBusy(true)
    try {
      const target = { url: targetUrl, token: targetToken }
      // A locked client must authenticate before it may disarm. The same code
      // serves both steps: turning 2FA off verifies a code without spending a
      // step, so it is still valid after the sign-in that precedes it.
      if (locked) await unlockTwoFactor(target, code.trim())
      await disableTwoFactor(target, code.trim())
      setLocked(false)
      setEnabled(false)
      setDisarming(false)
      setCode('')
      toast.success('Two-factor authentication disabled.')
    } catch (error) {
      toast.error(getErrorMessage(error))
    } finally {
      setBusy(false)
    }
  }, [targetUrl, targetToken, code, locked])

  if (enabled === null) return null

  return (
    <SettingsSection
      title="Two-factor authentication"
      description={
        enabled
          ? 'Signing in requires a code from your authenticator app. The access token on its own no longer opens a session.'
          : 'Require a code from an authenticator app on top of the access token. Recommended before exposing this server to the internet.'
      }
    >
      {enabled ? (
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <ShieldCheck className="size-4 text-emerald-500" />
            Enabled
          </div>
          {disarming ? (
            <div className="space-y-2">
              <Label htmlFor="two-factor-disable-code">
                Enter a current code to turn it off
              </Label>
              <div className="flex flex-wrap gap-2">
                <Input
                  id="two-factor-disable-code"
                  className="w-40 font-mono"
                  autoComplete="one-time-code"
                  inputMode="numeric"
                  maxLength={6}
                  value={code}
                  onChange={event => setCode(event.target.value)}
                  placeholder="6-digit code"
                />
                <Button
                  variant="destructive"
                  disabled={busy || !code.trim()}
                  onClick={handleDisable}
                >
                  Turn off
                </Button>
                <Button
                  variant="ghost"
                  onClick={() => {
                    setDisarming(false)
                    setCode('')
                  }}
                >
                  Cancel
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">
                Lost the device? Run <code>jean-server --disable-2fa</code> on
                the machine itself, then restart the server.
              </p>
            </div>
          ) : (
            <Button variant="outline" onClick={() => setDisarming(true)}>
              <ShieldOff className="size-4" />
              Turn off
            </Button>
          )}
        </div>
      ) : enrollment ? (
        <div className="space-y-3">
          <p className="text-sm text-muted-foreground">
            Scan this with your authenticator app, then enter the code it shows
            to confirm.
          </p>
          {qrDataUrl && (
            <img
              src={qrDataUrl}
              alt="Two-factor enrollment QR code"
              width={200}
              height={200}
              className="rounded-md bg-white p-2"
            />
          )}
          <div className="flex flex-wrap items-center gap-2">
            <Input
              className="w-72 font-mono text-xs"
              value={enrollment.secret}
              readOnly
              aria-label="Setup key"
            />
            <Button
              variant="ghost"
              onClick={() => {
                void copyToClipboard(enrollment.secret)
                toast.success('Setup key copied')
              }}
            >
              Copy setup key
            </Button>
          </div>
          <div className="space-y-2">
            <Label htmlFor="two-factor-confirm-code">
              Code from the app
            </Label>
            <div className="flex flex-wrap gap-2">
              <Input
                id="two-factor-confirm-code"
                className="w-40 font-mono"
                autoComplete="one-time-code"
                inputMode="numeric"
                maxLength={6}
                value={code}
                onChange={event => setCode(event.target.value)}
                placeholder="6-digit code"
              />
              <Button disabled={busy || !code.trim()} onClick={handleConfirm}>
                Confirm
              </Button>
              <Button
                variant="ghost"
                onClick={() => {
                  setEnrollment(null)
                  setCode('')
                }}
              >
                Cancel
              </Button>
            </div>
          </div>
        </div>
      ) : (
        <Button variant="outline" disabled={busy} onClick={handleEnroll}>
          <ShieldCheck className="size-4" />
          Set up two-factor authentication
        </Button>
      )}
    </SettingsSection>
  )
}
