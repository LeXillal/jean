import { describe, expect, it, vi } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { InstanceSessionsSection } from './InstanceSessionsSection'
import type { InstanceSession, JeanInstance } from '@/services/instances'
import type { Session } from '@/types/chat'

function makeInstanceSession(
  overrides: Partial<InstanceSession> = {}
): InstanceSession {
  return {
    instanceId: 'a',
    instanceName: 'Server A',
    projectId: 'p1',
    projectName: 'Jean',
    worktreeId: 'w1',
    worktreeName: 'feat-login',
    worktreePath: '/root/dev/jean',
    session: {
      id: 's1',
      name: 'Fix the proxy',
      order: 0,
      created_at: 1,
      updated_at: 2,
      messages: [],
    } as Session,
    status: 'idle',
    unread: false,
    key: 'a::s1',
    ...overrides,
  }
}

function instance(overrides: Partial<JeanInstance> = {}): JeanInstance {
  return {
    id: 'a',
    name: 'Server A',
    status: 'connected',
    isFocused: false,
    aggregate: true,
    ...overrides,
  }
}

describe('InstanceSessionsSection', () => {
  it('lists the sessions under the instance name', () => {
    render(
      <InstanceSessionsSection
        instance={instance()}
        sessions={[makeInstanceSession()]}
        onOpenSession={vi.fn()}
        onNewSession={vi.fn()}
      />
    )

    expect(screen.getByText('Server A')).toBeInTheDocument()
    expect(screen.getByText('Fix the proxy')).toBeInTheDocument()
    expect(screen.getByText('feat-login')).toBeInTheDocument()
  })

  it('hands the clicked session back with its instance attached', () => {
    const onOpenSession = vi.fn()
    const item = makeInstanceSession()

    render(
      <InstanceSessionsSection
        instance={instance()}
        sessions={[item]}
        onOpenSession={onOpenSession}
        onNewSession={vi.fn()}
      />
    )

    fireEvent.click(screen.getByText('Fix the proxy'))

    expect(onOpenSession).toHaveBeenCalledWith(
      expect.objectContaining({ instanceId: 'a', key: 'a::s1' })
    )
  })

  it('shows why an unreachable instance has no sessions', () => {
    render(
      <InstanceSessionsSection
        instance={instance({ status: 'offline' })}
        sessions={[]}
        onOpenSession={vi.fn()}
        onNewSession={vi.fn()}
      />
    )

    expect(screen.getByText('Offline — retrying')).toBeInTheDocument()
    expect(screen.queryByText('No sessions')).not.toBeInTheDocument()
  })

  it('never renders stale rows for an instance that went offline', () => {
    // Sessions stay in the query cache after a drop; showing them as if they
    // were current would misreport a server that is not answering.
    render(
      <InstanceSessionsSection
        instance={instance({ status: 'auth-error' })}
        sessions={[makeInstanceSession()]}
        onOpenSession={vi.fn()}
        onNewSession={vi.fn()}
      />
    )

    expect(screen.queryByText('Fix the proxy')).not.toBeInTheDocument()
    expect(screen.getByText('Authentication failed')).toBeInTheDocument()
  })

  it('collapses and expands the section', () => {
    render(
      <InstanceSessionsSection
        instance={instance()}
        sessions={[makeInstanceSession()]}
        onOpenSession={vi.fn()}
        onNewSession={vi.fn()}
      />
    )

    const header = screen.getByRole('button', { expanded: true })
    fireEvent.click(header)

    expect(screen.queryByText('Fix the proxy')).not.toBeInTheDocument()
  })

  it('offers a way in when the instance has no session', () => {
    // Without this row an empty instance is only reachable from the connection
    // picker: there is nothing else to click in its section.
    const onNewSession = vi.fn()

    render(
      <InstanceSessionsSection
        instance={instance()}
        sessions={[]}
        onOpenSession={vi.fn()}
        onNewSession={onNewSession}
      />
    )

    fireEvent.click(screen.getByText('New session'))

    expect(onNewSession).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'a' })
    )
  })

  it('starts a session from the header of a populated instance', () => {
    const onNewSession = vi.fn()

    render(
      <InstanceSessionsSection
        instance={instance()}
        sessions={[makeInstanceSession()]}
        onOpenSession={vi.fn()}
        onNewSession={onNewSession}
      />
    )

    fireEvent.click(screen.getByLabelText('New session on Server A'))

    expect(onNewSession).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'a' })
    )
  })

  it('offers no new session on an unreachable instance', () => {
    render(
      <InstanceSessionsSection
        instance={instance({ status: 'offline' })}
        sessions={[]}
        onOpenSession={vi.fn()}
        onNewSession={vi.fn()}
      />
    )

    expect(
      screen.queryByLabelText('New session on Server A')
    ).not.toBeInTheDocument()
    expect(screen.queryByText('New session')).not.toBeInTheDocument()
  })

  it('marks an unread session', () => {
    render(
      <InstanceSessionsSection
        instance={instance()}
        sessions={[makeInstanceSession({ unread: true })]}
        onOpenSession={vi.fn()}
        onNewSession={vi.fn()}
      />
    )

    expect(screen.getByLabelText('Unread')).toBeInTheDocument()
  })
})
