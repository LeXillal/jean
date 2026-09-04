import { useCallback, useEffect, useMemo } from 'react'
import {
  markConnectionSwitch,
  selectConnection,
} from '@/lib/remote-connections'
import { isNativeApp } from '@/lib/environment'
import {
  consumePendingNewSession,
  consumePendingSessionOpen,
  groupSessionsByProject,
  setPendingNewSession,
  setPendingSessionOpen,
  satelliteInstances,
  useInstanceSessions,
  useInstances,
  useSatelliteSessionRefresh,
  useSatelliteTransports,
  type InstanceSession,
  type JeanInstance,
} from '@/services/instances'
import { openNewWorktree } from '@/lib/open-new-worktree'
import { useChatStore } from '@/store/chat-store'
import { useProjectsStore } from '@/store/projects-store'
import { InstanceSessionsSection } from './InstanceSessionsSection'

/**
 * Replay a session open that was requested on another instance before the
 * connection switch reloaded the page.
 *
 * Mirrors `WorktreeItem`'s own select-then-open sequence, including the short
 * delay that lets the canvas mount its `open-session-modal` listener.
 */
function usePendingSessionOpen(ready: boolean): void {
  useEffect(() => {
    if (!ready) return
    const pending = consumePendingSessionOpen()
    if (!pending) return

    useProjectsStore.getState().selectProject(pending.projectId)
    useProjectsStore.getState().selectWorktree(pending.worktreeId)
    useChatStore.getState().clearActiveWorktree()
    useChatStore
      .getState()
      .setActiveSession(pending.worktreeId, pending.sessionId)

    const timer = setTimeout(() => {
      window.dispatchEvent(
        new CustomEvent('open-session-modal', {
          detail: {
            sessionId: pending.sessionId,
            worktreeId: pending.worktreeId,
            worktreePath: pending.worktreePath,
          },
        })
      )
    }, 50)
    return () => clearTimeout(timer)
  }, [ready])
}

/**
 * Replay a "new session here" request made on another instance before the
 * connection switch reloaded the page.
 *
 * No project is passed: the composer opens on whatever the target instance has
 * selected, which is the only project identity that means anything here —
 * project ids are per-instance.
 */
function usePendingNewSession(ready: boolean): void {
  useEffect(() => {
    if (!ready) return
    if (!consumePendingNewSession()) return
    openNewWorktree()
  }, [ready])
}

interface SatelliteInstancesProps {
  /** True once the focused instance's own projects have loaded. */
  ready: boolean
}

/**
 * Sessions from every Jean instance that is NOT the focused one and has sidebar
 * aggregation enabled, grouped under a header per instance.
 *
 * The focused instance keeps its full project tree above; these sections are
 * the aggregated half of the sidebar. Native desktop is excluded: it has no
 * hub to relay background connections through.
 */
export function SatelliteInstances({ ready }: SatelliteInstancesProps) {
  const instances = useInstances()
  // Empty on native so the fan-out below issues no queries at all: `invokeOn`
  // would otherwise build a WebSocket transport per registered remote that can
  // never connect, leaking its wake listeners and hanging on the command
  // timeout — all for a component that renders null here.
  const satellites = useMemo(
    () => (isNativeApp() ? [] : satelliteInstances(instances)),
    [instances]
  )

  useSatelliteTransports(instances)
  useSatelliteSessionRefresh(instances)
  usePendingSessionOpen(ready)
  usePendingNewSession(ready)

  const sessions = useInstanceSessions(satellites)

  const groups = useMemo(
    () => groupSessionsByProject(sessions, satellites),
    [sessions, satellites]
  )

  const handleOpenSession = useCallback((item: InstanceSession) => {
    // The target lives on another server: record it, then switch. The reload
    // is the existing switch flow; `usePendingSessionOpen` finishes the job.
    setPendingSessionOpen({
      instanceId: item.instanceId,
      projectId: item.projectId,
      worktreeId: item.worktreeId,
      worktreePath: item.worktreePath,
      sessionId: item.session.id,
    })
    markConnectionSwitch()
    selectConnection(item.instanceId)
    window.location.reload()
  }, [])

  const handleNewSession = useCallback((instance: JeanInstance) => {
    // Same switch, with no session to reopen: `usePendingNewSession` opens the
    // composer once the target instance is in focus.
    setPendingNewSession(instance.id)
    markConnectionSwitch()
    selectConnection(instance.id)
    window.location.reload()
  }, [])

  if (isNativeApp() || satellites.length === 0) return null

  return (
    <div className="border-t border-border/50 pt-1">
      {groups.map(group => (
        <InstanceSessionsSection
          key={group.key}
          instance={group.instance}
          projectName={group.projectName}
          sessions={group.sessions}
          onOpenSession={handleOpenSession}
          onNewSession={handleNewSession}
        />
      ))}
    </div>
  )
}
