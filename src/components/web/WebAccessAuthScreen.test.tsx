import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@/test/test-utils'
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

    expect(onTokenSubmit).toHaveBeenCalledWith('secret-token')
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

  it('hides the form when the server cannot be reached', () => {
    render(
      <WebAccessAuthScreen
        authError="Jean could not reach the server."
        reason="unreachable"
        onTokenSubmit={vi.fn()}
      />
    )

    // Pasting a token cannot fix an unreachable server, so don't ask for one.
    expect(screen.queryByLabelText(/access token/i)).not.toBeInTheDocument()
    expect(screen.getByRole('alert')).toHaveTextContent(/could not reach/i)
  })
})
