import { beforeEach, describe, expect, it, vi } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { createElement, type ReactNode } from 'react'
import type { AllSessionsResponse, Session } from '@/types/chat'

const noop = () => undefined

const {
  invokeOn,
  listenOn,
  getInstanceStatus,
  ensureSatelliteTransport,
  releaseTransport,
  liveTransportIds,
} = vi.hoisted(() => ({
  invokeOn: vi.fn(),
  listenOn: vi.fn(async () => noop),
  getInstanceStatus: vi.fn(() => 'connected'),
  ensureSatelliteTransport: vi.fn(),
  releaseTransport: vi.fn(),
  liveTransportIds: { current: [] as string[] },
}))

vi.mock('@/lib/transport', () => ({
  ensureSatelliteTransport,
  getInstanceStatus,
  getLiveTransportIds: () => liveTransportIds.current,
  getTransportRegistryVersion: () => 0,
  invokeOn,
  listenOn,
  releaseTransport,
  subscribeToTransports: () => noop,
}))

vi.mock('@/lib/environment', () => ({
  isNativeApp: () => false,
}))

import {
  consumePendingSessionOpen,
  deriveSatelliteSessionStatus,
  instanceSessionKey,
  satelliteInstances,
  setPendingSessionOpen,
  useInstanceSessions,
  useSatelliteTransports,
  type JeanInstance,
} from './instances'

function makeSession(overrides: Partial<Session> = {}): Session {
  return {
    id: 'session-1',
    name: 'Session 1',
    order: 0,
    created_at: 1,
    updated_at: 2,
    messages: [],
    ...overrides,
  } as Session
}

function makeResponse(
  worktreeId: string,
  sessions: Session[]
): AllSessionsResponse {
  return {
    entries: [
      {
        project_id: 'project-1',
        project_name: 'Jean',
        worktree_id: worktreeId,
        worktree_name: 'main',
        worktree_path: '/root/dev/jean',
        sessions,
      },
    ],
  }
}

function instance(
  id: string,
  name: string,
  overrides: Partial<JeanInstance> = {}
): JeanInstance {
  return {
    id,
    name,
    status: 'connected',
    isFocused: false,
    aggregate: true,
    ...overrides,
  }
}

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  })
  return createElement(QueryClientProvider, { client }, children)
}

describe('deriveSatelliteSessionStatus', () => {
  it('reports a running session', () => {
    expect(
      deriveSatelliteSessionStatus(makeSession({ last_run_status: 'running' }))
    ).toBe('running')
  })

  it('reports a session waiting for input', () => {
    expect(
      deriveSatelliteSessionStatus(makeSession({ waiting_for_input: true }))
    ).toBe('waiting')
  })

  it('treats a pending approval queue as waiting', () => {
    expect(
      deriveSatelliteSessionStatus(
        makeSession({
          pending_codex_permission_requests: [
            { id: 'p1' },
          ] as unknown as Session['pending_codex_permission_requests'],
        })
      )
    ).toBe('waiting')
  })

  it('prefers an explicit review override over the run status', () => {
    expect(
      deriveSatelliteSessionStatus(
        makeSession({ status_override: 'review', last_run_status: 'completed' })
      )
    ).toBe('review')
  })

  it('falls back to idle for a finished session', () => {
    expect(
      deriveSatelliteSessionStatus(
        makeSession({ last_run_status: 'completed' })
      )
    ).toBe('idle')
  })
})

describe('pending session open', () => {
  beforeEach(() => {
    window.sessionStorage.clear()
  })

  it('replays a target that belongs to the instance now in focus', () => {
    setPendingSessionOpen({
      instanceId: 'local',
      projectId: 'p',
      worktreeId: 'w',
      worktreePath: '/w',
      sessionId: 's',
    })

    expect(consumePendingSessionOpen()).toMatchObject({ sessionId: 's' })
  })

  it('drops a target left over from another instance', () => {
    setPendingSessionOpen({
      instanceId: 'some-other-server',
      projectId: 'p',
      worktreeId: 'w',
      worktreePath: '/w',
      sessionId: 's',
    })

    expect(consumePendingSessionOpen()).toBeNull()
  })

  it('consumes the target exactly once', () => {
    setPendingSessionOpen({
      instanceId: 'local',
      projectId: 'p',
      worktreeId: 'w',
      worktreePath: '/w',
      sessionId: 's',
    })

    expect(consumePendingSessionOpen()).not.toBeNull()
    expect(consumePendingSessionOpen()).toBeNull()
  })
})

describe('useInstanceSessions', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('tags every session with the instance it was fetched from', async () => {
    invokeOn.mockImplementation(async (instanceId: string) =>
      makeResponse('wt-1', [makeSession({ id: `${instanceId}-session` })])
    )

    const { result } = renderHook(
      () => useInstanceSessions([instance('a', 'Server A')]),
      { wrapper }
    )

    await waitFor(() => expect(result.current).toHaveLength(1))
    expect(result.current[0]).toMatchObject({
      instanceId: 'a',
      instanceName: 'Server A',
      worktreeId: 'wt-1',
    })
  })

  it('keeps identical ids from two instances apart', async () => {
    // Jean derives worktree identity from the absolute path, so the same repo
    // cloned at the same path on two machines produces the SAME worktree id.
    invokeOn.mockImplementation(async () =>
      makeResponse('shared-worktree-id', [makeSession({ id: 'shared-id' })])
    )

    const { result } = renderHook(
      () =>
        useInstanceSessions([
          instance('a', 'Server A'),
          instance('b', 'Server B'),
        ]),
      { wrapper }
    )

    await waitFor(() => expect(result.current).toHaveLength(2))
    const keys = result.current.map(item => item.key)
    expect(new Set(keys).size).toBe(2)
    expect(keys).toContain(instanceSessionKey('a', 'shared-id'))
    expect(keys).toContain(instanceSessionKey('b', 'shared-id'))
  })

  it('keeps the other instances when one fails', async () => {
    invokeOn.mockImplementation(async (instanceId: string) => {
      if (instanceId === 'a') throw new Error('offline')
      return makeResponse('wt-b', [makeSession({ id: 'b-session' })])
    })

    const { result } = renderHook(
      () =>
        useInstanceSessions([
          instance('a', 'Server A'),
          instance('b', 'Server B'),
        ]),
      { wrapper }
    )

    await waitFor(() => expect(result.current).toHaveLength(1))
    expect(result.current[0]?.instanceId).toBe('b')
  })

  it('hides archived sessions and sorts by most recent activity', async () => {
    invokeOn.mockImplementation(async () =>
      makeResponse('wt-1', [
        makeSession({ id: 'old', updated_at: 10 }),
        makeSession({ id: 'archived', updated_at: 99, archived_at: 5 }),
        makeSession({ id: 'recent', updated_at: 50 }),
      ])
    )

    const { result } = renderHook(
      () => useInstanceSessions([instance('a', 'Server A')]),
      { wrapper }
    )

    await waitFor(() => expect(result.current).toHaveLength(2))
    expect(result.current.map(item => item.session.id)).toEqual([
      'recent',
      'old',
    ])
  })
})

describe('sidebar aggregation opt-out', () => {
  beforeEach(() => {
    ensureSatelliteTransport.mockClear()
    releaseTransport.mockClear()
    liveTransportIds.current = []
  })

  it('excludes the focused instance and the opted-out ones', () => {
    const instances = [
      instance('local', 'This server', { isFocused: true }),
      instance('a', 'A'),
      instance('b', 'B', { aggregate: false }),
    ]
    expect(satelliteInstances(instances).map(item => item.id)).toEqual(['a'])
  })

  it('opens no background transport for an opted-out instance', () => {
    renderHook(
      () =>
        useSatelliteTransports([
          instance('local', 'This server', { isFocused: true }),
          instance('a', 'A'),
          instance('b', 'B', { aggregate: false }),
        ]),
      { wrapper }
    )

    expect(ensureSatelliteTransport).toHaveBeenCalledTimes(1)
    expect(ensureSatelliteTransport).toHaveBeenCalledWith('a')
  })

  it('releases the transport of an instance that was just opted out', () => {
    liveTransportIds.current = ['local', 'b']
    renderHook(
      () =>
        useSatelliteTransports([
          instance('local', 'This server', { isFocused: true }),
          instance('b', 'B', { aggregate: false }),
        ]),
      { wrapper }
    )

    expect(releaseTransport).toHaveBeenCalledWith('b')
    // The focused instance drives the main UI: never release it.
    expect(releaseTransport).not.toHaveBeenCalledWith('local')
  })
})
