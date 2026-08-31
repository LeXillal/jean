/**
 * Multi-instance aggregation.
 *
 * The sidebar shows sessions from every registered Jean server at once, not
 * just the selected one. The focused instance keeps its full project tree;
 * every other instance is read through a background ("satellite") transport.
 *
 * Two invariants hold everywhere in this file:
 *
 * 1. **Provenance is by construction.** A remote never says which instance it
 *    is — the hub does, because it chose the transport. So every aggregated
 *    row is tagged at the point of the fan-out, never inferred afterwards.
 * 2. **Ids are only unique per instance.** Jean derives project/worktree
 *    identity from absolute paths, so the same repo cloned at the same path on
 *    two machines yields the *same* worktree id. Anything cached or keyed
 *    across instances must therefore be keyed by `(instanceId, id)`.
 */

import { useEffect, useMemo, useSyncExternalStore } from 'react'
import { useQueries, useQueryClient } from '@tanstack/react-query'
import {
  LOCAL_CONNECTION_ID,
  getActiveConnectionId,
  useRemoteConnections,
} from '@/lib/remote-connections'
import {
  ensureSatelliteTransport,
  getInstanceStatus,
  getLiveTransportIds,
  getTransportRegistryVersion,
  invokeOn,
  listenOn,
  releaseTransport,
  subscribeToTransports,
  type InstanceStatus,
} from '@/lib/transport'
import { isNativeApp } from '@/lib/environment'
import {
  hasPendingSessionApproval,
  isUnreadSession,
} from '@/components/unread/unread-utils'
import type { AllSessionsResponse, Session } from '@/types/chat'
import { createLogger } from '@/lib/logger'

const logger = createLogger('instances')

/** Label shown for the server the browser is talking to directly. */
export const LOCAL_INSTANCE_NAME = 'This server'

export interface JeanInstance {
  id: string
  name: string
  status: InstanceStatus
  /** The instance the main UI is currently driving. */
  isFocused: boolean
}

/** A session plus the instance it belongs to. */
export interface InstanceSession {
  instanceId: string
  instanceName: string
  projectId: string
  projectName: string
  worktreeId: string
  worktreeName: string
  worktreePath: string
  session: Session
  status: SatelliteSessionStatus
  unread: boolean
  /** Stable across instances, unlike `session.id` on its own. */
  key: string
}

export function instanceSessionKey(
  instanceId: string,
  sessionId: string
): string {
  return `${instanceId}::${sessionId}`
}

/** Status shown for a session that belongs to a non-focused instance. */
export type SatelliteSessionStatus = 'running' | 'waiting' | 'review' | 'idle'

/**
 * Derive a session's status from the persisted record alone.
 *
 * Satellite sessions deliberately do NOT go through `computeSessionCardData`:
 * that reads live chat-store state, which only ever holds the focused
 * instance. Everything below comes from fields the backend already persists,
 * so a remote session reports the same status whether or not it is focused.
 */
export function deriveSatelliteSessionStatus(
  session: Session
): SatelliteSessionStatus {
  if (session.status_override === 'review') return 'review'
  if (session.last_run_status === 'running') return 'running'
  if (session.waiting_for_input || hasPendingSessionApproval(session)) {
    return 'waiting'
  }
  if (session.is_reviewing || session.review_results) return 'review'
  return 'idle'
}

export function instanceSessionsQueryKey(instanceId: string) {
  return ['instance-sessions', instanceId] as const
}

// ---------------------------------------------------------------------------
// Deferred "open this session" across a connection switch
// ---------------------------------------------------------------------------

const PENDING_OPEN_KEY = 'jean-pending-session-open'

export interface PendingSessionOpen {
  instanceId: string
  projectId: string
  worktreeId: string
  worktreePath: string
  sessionId: string
}

/**
 * Remember which session to open once the app has switched instances.
 *
 * Switching still reloads the page, so the click target cannot be honoured
 * in-place; it is replayed after boot. `sessionStorage` (not `localStorage`)
 * keeps it scoped to this tab and short-lived.
 */
export function setPendingSessionOpen(target: PendingSessionOpen): void {
  if (typeof window === 'undefined') return
  window.sessionStorage.setItem(
    PENDING_OPEN_KEY,
    JSON.stringify({ ...target, requestedAt: Date.now() })
  )
}

/** A switch that has not completed within this window is abandoned. */
const PENDING_OPEN_TTL_MS = 60_000

/**
 * Read the pending target, but only when it belongs to the instance now in
 * focus — it must never open a session on the wrong server.
 *
 * A target for another instance is deliberately kept: the switch it belongs to
 * may still be in flight, and consuming it here would silently make the click
 * do nothing. The timestamp bounds how long that can last.
 */
export function consumePendingSessionOpen(): PendingSessionOpen | null {
  if (typeof window === 'undefined') return null
  const raw = window.sessionStorage.getItem(PENDING_OPEN_KEY)
  if (!raw) return null

  let parsed: (PendingSessionOpen & { requestedAt?: number }) | null = null
  try {
    parsed = JSON.parse(raw)
  } catch {
    window.sessionStorage.removeItem(PENDING_OPEN_KEY)
    return null
  }

  if (!parsed?.sessionId || !parsed.worktreeId) {
    window.sessionStorage.removeItem(PENDING_OPEN_KEY)
    return null
  }
  if (Date.now() - (parsed.requestedAt ?? 0) > PENDING_OPEN_TTL_MS) {
    window.sessionStorage.removeItem(PENDING_OPEN_KEY)
    return null
  }
  if (parsed.instanceId !== getActiveConnectionId()) return null

  window.sessionStorage.removeItem(PENDING_OPEN_KEY)
  return parsed
}

/**
 * Every registered instance, the local one first, with its live status.
 *
 * Subscribes to a version counter rather than a computed array: building a new
 * array inside `getSnapshot` would make `useSyncExternalStore` loop forever.
 */
export function useInstances(): JeanInstance[] {
  const connections = useRemoteConnections()
  const version = useSyncExternalStore(
    subscribeToTransports,
    getTransportRegistryVersion,
    () => 0
  )
  const activeId = getActiveConnectionId()

  return useMemo(() => {
    void version
    const entries = [
      { id: LOCAL_CONNECTION_ID, name: LOCAL_INSTANCE_NAME },
      ...connections.map(item => ({ id: item.id, name: item.name })),
    ]
    return entries.map(entry => ({
      ...entry,
      status: getInstanceStatus(entry.id),
      isFocused: entry.id === activeId,
    }))
  }, [connections, version, activeId])
}

/**
 * Open a background transport for every non-focused instance, and close the
 * ones whose connection was deleted.
 *
 * Native desktop is excluded: it drives its local backend over Tauri IPC and
 * has no hub to relay satellites through.
 */
export function useSatelliteTransports(instances: JeanInstance[]): void {
  const wantedIds = useMemo(
    () =>
      instances
        .filter(instance => !instance.isFocused)
        .map(instance => instance.id)
        .join(','),
    [instances]
  )

  useEffect(() => {
    if (isNativeApp()) return
    const wanted = wantedIds ? wantedIds.split(',') : []
    for (const id of wanted) ensureSatelliteTransport(id)

    // Drop transports for connections that disappeared from the list, so a
    // deleted remote stops holding a socket open.
    const focusedId = getActiveConnectionId()
    for (const id of getLiveTransportIds()) {
      if (id === focusedId || wanted.includes(id)) continue
      logger.debug('Releasing transport for removed instance', { id })
      releaseTransport(id)
    }
  }, [wantedIds])
}

/**
 * Keep each satellite's session list fresh from its own `cache:invalidate`
 * stream. This is what makes a remote session's status change show up in the
 * sidebar while you are working on another instance — without routing that
 * instance's chat events into the (focused-only) chat store.
 */
export function useSatelliteSessionRefresh(instances: JeanInstance[]): void {
  const queryClient = useQueryClient()
  const satelliteIds = useMemo(
    () =>
      instances
        .filter(instance => !instance.isFocused)
        .map(instance => instance.id)
        .join(','),
    [instances]
  )

  useEffect(() => {
    if (isNativeApp() || !satelliteIds) return
    const ids = satelliteIds.split(',')
    const unlisteners: (() => void)[] = []
    const timers = new Map<string, ReturnType<typeof setTimeout>>()
    let cancelled = false

    const scheduleRefresh = (instanceId: string) => {
      const existing = timers.get(instanceId)
      if (existing) clearTimeout(existing)
      // Coalesce a burst of backend invalidations into one refetch, the way
      // the focused client already does for its own cache keys.
      timers.set(
        instanceId,
        setTimeout(() => {
          timers.delete(instanceId)
          void queryClient.invalidateQueries({
            queryKey: instanceSessionsQueryKey(instanceId),
          })
        }, 250)
      )
    }

    for (const id of ids) {
      void listenOn<{ keys: string[] }>(id, 'cache:invalidate', event => {
        if (!event.payload?.keys?.includes('sessions')) return
        scheduleRefresh(event.instanceId)
      }).then(unlisten => {
        if (cancelled) {
          unlisten()
          return
        }
        unlisteners.push(unlisten)
      })
    }

    return () => {
      cancelled = true
      for (const timer of timers.values()) clearTimeout(timer)
      timers.clear()
      for (const unlisten of unlisteners) unlisten()
    }
  }, [satelliteIds, queryClient])
}

/**
 * Fan `list_all_sessions` out over the given instances.
 *
 * One query per instance (never one merged query): a slow or offline instance
 * must not stall or empty the others, and each has its own cache entry to
 * invalidate.
 */
export function useInstanceSessions(instances: JeanInstance[]) {
  const nameById = useMemo(
    () => new Map(instances.map(instance => [instance.id, instance.name])),
    [instances]
  )

  const results = useQueries({
    queries: instances.map(instance => ({
      queryKey: instanceSessionsQueryKey(instance.id),
      queryFn: async (): Promise<AllSessionsResponse> => {
        try {
          return await invokeOn<AllSessionsResponse>(
            instance.id,
            'list_all_sessions'
          )
        } catch (error) {
          logger.warn('Failed to load sessions for instance', {
            instanceId: instance.id,
            error,
          })
          return { entries: [] }
        }
      },
      // An unreachable instance should not be retried aggressively; its
      // transport reconnect already drives recovery.
      retry: false,
      staleTime: 1000 * 30,
      gcTime: 1000 * 60 * 5,
    })),
  })

  // `useQueries` returns a fresh array every render, so memoize on the
  // per-query update stamps instead — they change exactly when data does.
  const updateStamps = results.map(result => result.dataUpdatedAt).join('|')

  return useMemo(() => {
    const sessions: InstanceSession[] = []
    results.forEach((result, index) => {
      const instance = instances[index]
      if (!instance || !result.data) return
      const instanceName = nameById.get(instance.id) ?? instance.id
      for (const entry of result.data.entries) {
        for (const session of entry.sessions) {
          if (session.archived_at) continue
          sessions.push({
            instanceId: instance.id,
            instanceName,
            projectId: entry.project_id,
            projectName: entry.project_name,
            worktreeId: entry.worktree_id,
            worktreeName: entry.worktree_name,
            worktreePath: entry.worktree_path,
            session,
            status: deriveSatelliteSessionStatus(session),
            unread: isUnreadSession(session),
            key: instanceSessionKey(instance.id, session.id),
          })
        }
      }
    })
    // Most recently active first, across every instance — that ordering is the
    // whole point of an aggregated view.
    sessions.sort((a, b) => b.session.updated_at - a.session.updated_at)
    return sessions
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [updateStamps, instances, nameById])
}
