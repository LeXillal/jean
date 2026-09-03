import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen, waitFor } from '@/test/test-utils'
import { WebAccessAuthScreen } from './WebAccessAuthScreen'

describe('WebAccessAuthScreen', () => {
  it('lets the user submit an access token from the browser UI', async () => {
    const onTokenSubmit = vi.fn()

    render(
      <WebAccessAuthScreen
        authError="Enter the access token."
        onTokenSubmit={onTokenSubmit}
      />
    )

    fireEvent.change(screen.getByLabelText(/access token/i), {
      target: { value: 'secret-token' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    // No code is sent until the server asks for one.
    expect(onTokenSubmit).toHaveBeenCalledWith('secret-token', undefined)

    // Submitting reloads the page; the button stays locked until then so the
    // user gets feedback and cannot double-submit.
    expect(screen.getByRole('button', { name: /signing in/i })).toBeDisabled()
  })

  it('does not submit blank tokens', async () => {
    const onTokenSubmit = vi.fn()

    render(
      <WebAccessAuthScreen
        authError="Enter the access token."
        onTokenSubmit={onTokenSubmit}
      />
    )

    fireEvent.change(screen.getByLabelText(/access token/i), {
      target: { value: '   ' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    expect(onTokenSubmit).not.toHaveBeenCalled()
    expect(screen.getByText(/enter the access token/i)).toBeInTheDocument()
  })

  it('greets a first visit instead of reporting a failure', () => {
    render(
      <WebAccessAuthScreen
        authError="Enter the access token from Jean's Web Access settings."
        reason="signed-out"
        onTokenSubmit={vi.fn()}
      />
    )

    expect(
      screen.getByRole('heading', { name: /sign in to jean/i })
    ).toBeInTheDocument()
    // A first visit has failed at nothing — no alert should be raised.
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
  })

  it('flags the field when the server refused the token', () => {
    render(
      <WebAccessAuthScreen
        authError="That access token was refused."
        reason="rejected"
        onTokenSubmit={vi.fn()}
      />
    )

    expect(screen.getByRole('alert')).toHaveTextContent(/refused/i)
    expect(screen.getByLabelText(/access token/i)).toHaveAttribute(
      'aria-invalid',
      'true'
    )
  })

  it('clears the refused-token alert once the user edits the field', () => {
    render(
      <WebAccessAuthScreen
        authError="That access token was refused."
        reason="rejected"
        onTokenSubmit={vi.fn()}
      />
    )

    fireEvent.change(screen.getByLabelText(/access token/i), {
      target: { value: 'fresh-token' },
    })

    // The alert described the previous submission — a fresh entry has not
    // failed at anything yet.
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()
    expect(screen.getByLabelText(/access token/i)).toHaveAttribute(
      'aria-invalid',
      'false'
    )
  })

  it('always offers the token form — submitting reloads, which is how a lost connection recovers', () => {
    render(
      <WebAccessAuthScreen
        authError="Connection to the server was lost."
        onTokenSubmit={vi.fn()}
      />
    )

    expect(screen.getByLabelText(/access token/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /sign in/i })).toBeEnabled()
  })

  it('asks for a code only after the server says the token needs one', async () => {
    const onTokenSubmit = vi
      .fn()
      // First submission: token accepted, second factor pending.
      .mockResolvedValueOnce({
        ok: false,
        codeRequired: true,
        error: 'Enter the code from your authenticator app',
      })
      .mockResolvedValueOnce({ ok: true })

    render(
      <WebAccessAuthScreen
        authError="Enter the access token."
        onTokenSubmit={onTokenSubmit}
      />
    )

    // The code field must not exist before the server asks: its presence would
    // tell anyone loading the page that this server has 2FA enrolled.
    expect(screen.queryByLabelText(/authentication code/i)).toBeNull()

    fireEvent.change(screen.getByLabelText(/access token/i), {
      target: { value: 'secret-token' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    const codeField = await screen.findByLabelText(/authentication code/i)
    // Being asked is not a failure — no error until an attempt is made.
    expect(screen.queryByRole('alert')).not.toBeInTheDocument()

    fireEvent.change(codeField, { target: { value: '123456' } })
    fireEvent.click(screen.getByRole('button', { name: /verify/i }))

    await waitFor(() =>
      expect(onTokenSubmit).toHaveBeenLastCalledWith('secret-token', '123456')
    )
  })

  it('reports a refused code and lets the user try the next one', async () => {
    const onTokenSubmit = vi
      .fn()
      .mockResolvedValueOnce({
        ok: false,
        codeRequired: true,
        error: 'Enter the code from your authenticator app',
      })
      .mockResolvedValueOnce({
        ok: false,
        codeRequired: true,
        error: 'Invalid code',
      })

    render(
      <WebAccessAuthScreen
        authError="Enter the access token."
        onTokenSubmit={onTokenSubmit}
      />
    )

    fireEvent.change(screen.getByLabelText(/access token/i), {
      target: { value: 'secret-token' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    const codeField = await screen.findByLabelText(/authentication code/i)
    fireEvent.change(codeField, { target: { value: '000000' } })
    fireEvent.click(screen.getByRole('button', { name: /verify/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid code')
    // The spent code is cleared and the form is usable again, because the next
    // code is only 30 seconds away.
    expect(screen.getByLabelText(/authentication code/i)).toHaveValue('')
    expect(screen.getByRole('button', { name: /verify/i })).toBeEnabled()
  })

  it('drops back to the token step when the token itself is refused', async () => {
    const onTokenSubmit = vi.fn().mockResolvedValue({
      ok: false,
      codeRequired: false,
      error: 'Invalid token',
    })

    render(
      <WebAccessAuthScreen
        authError="Enter the access token."
        onTokenSubmit={onTokenSubmit}
      />
    )

    fireEvent.change(screen.getByLabelText(/access token/i), {
      target: { value: 'wrong-token' },
    })
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid token')
    expect(screen.queryByLabelText(/authentication code/i)).toBeNull()
  })
})
