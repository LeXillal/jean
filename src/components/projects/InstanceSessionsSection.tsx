import { memo, useCallback, useState } from 'react'
import { ChevronDown, ChevronRight, Plus } from 'lucide-react'
import { StatusIndicator } from '@/components/ui/status-indicator'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { cn } from '@/lib/utils'
import type { InstanceSession, JeanInstance } from '@/services/instances'
import type { InstanceStatus } from '@/lib/transport'

const CONNECTION_LABEL: Record<InstanceStatus, string> = {
  idle: 'Not connected',
  connecting: 'Connecting…',
  connected: 'Connected',
  offline: 'Offline — retrying',
  'auth-error': 'Authentication failed',
}

const CONNECTION_DOT: Record<InstanceStatus, string> = {
  idle: 'bg-muted-foreground/40',
  connecting: 'bg-amber-500 animate-pulse',
  connected: 'bg-emerald-500',
  offline: 'bg-muted-foreground/40',
  'auth-error': 'bg-destructive',
}

interface InstanceSessionsSectionProps {
  instance: JeanInstance
  /**
   * The project this section groups. Undefined for the trailing "empty
   * instance" section, which falls back to the instance name in its header.
   */
  projectName?: string
  sessions: InstanceSession[]
  onOpenSession: (session: InstanceSession) => void
  onNewSession: (instance: JeanInstance) => void
}

/**
 * One collapsible section per (instance, project) among the non-focused Jean
 * instances — the header shows the project, not the instance it happens to live
 * on. A session-less or unreachable instance still gets one section (with no
 * project) so it stays reachable.
 *
 * Rows are read-only: they come from a background transport, so they carry no
 * live chat-store state. Clicking one switches focus to that instance and
 * opens the session there.
 *
 * The header's "+" does the same switch with no target, so a project with no
 * session — or an empty instance — is still reachable from here instead of only
 * from the connection picker.
 */
function InstanceSessionsSectionImpl({
  instance,
  projectName,
  sessions,
  onOpenSession,
  onNewSession,
}: InstanceSessionsSectionProps) {
  const [expanded, setExpanded] = useState(true)
  const toggle = useCallback(() => setExpanded(value => !value), [])

  const unreachable =
    instance.status === 'offline' || instance.status === 'auth-error'

  const title = projectName ?? instance.name
  const newSessionLabel = projectName
    ? `New session in ${projectName}`
    : `New session on ${instance.name}`

  const handleNewSession = useCallback(
    () => onNewSession(instance),
    [instance, onNewSession]
  )

  return (
    <div className="pb-1">
      {/* Not one button: the "+" is nested inside the header row. */}
      <div className="group/header flex w-full items-center gap-1.5 pl-2 pr-1 pb-1 pt-2">
        <button
          type="button"
          onClick={toggle}
          className="flex min-w-0 flex-1 items-center gap-1.5 text-left"
          aria-expanded={expanded}
        >
          {expanded ? (
            <ChevronDown className="size-3 shrink-0 opacity-50" />
          ) : (
            <ChevronRight className="size-3 shrink-0 opacity-50" />
          )}
          <Tooltip>
            <TooltipTrigger asChild>
              <span
                className={cn(
                  'size-1.5 shrink-0 rounded-full',
                  CONNECTION_DOT[instance.status]
                )}
                aria-label={CONNECTION_LABEL[instance.status]}
              />
            </TooltipTrigger>
            <TooltipContent>{CONNECTION_LABEL[instance.status]}</TooltipContent>
          </Tooltip>
          <span className="min-w-0 flex-1 truncate text-[11px] font-semibold uppercase tracking-wider text-muted-foreground/50">
            {title}
          </span>
          {sessions.length > 0 && (
            <span className="shrink-0 text-[11px] tabular-nums text-muted-foreground/40">
              {sessions.length}
            </span>
          )}
        </button>
        {!unreachable && (
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                type="button"
                onClick={handleNewSession}
                className="shrink-0 rounded p-0.5 text-muted-foreground/50 opacity-0 transition-opacity hover:bg-muted/60 hover:text-foreground focus-visible:opacity-100 group-hover/header:opacity-100"
                aria-label={newSessionLabel}
              >
                <Plus className="size-3.5" />
              </button>
            </TooltipTrigger>
            <TooltipContent>{newSessionLabel}</TooltipContent>
          </Tooltip>
        )}
      </div>

      {expanded &&
        (unreachable ? (
          <div className="px-2 pb-1 pl-7 text-xs text-muted-foreground/50">
            {CONNECTION_LABEL[instance.status]}
          </div>
        ) : sessions.length === 0 ? (
          <button
            type="button"
            onClick={handleNewSession}
            className="flex w-full items-center gap-2 rounded-md py-1 pl-7 pr-2 text-left text-xs text-muted-foreground/40 transition-colors hover:bg-muted/60 hover:text-muted-foreground"
          >
            <Plus className="size-3 shrink-0" />
            <span>New session</span>
          </button>
        ) : (
          sessions.map(item => (
            <button
              key={item.key}
              type="button"
              onClick={() => onOpenSession(item)}
              className="flex w-full items-center gap-2 rounded-md py-1 pl-7 pr-2 text-left transition-colors hover:bg-muted/60"
            >
              <StatusIndicator
                status={item.status}
                label={item.status}
                className="shrink-0"
              />
              <span className="min-w-0 flex-1 truncate text-sm">
                {item.session.name}
              </span>
              {item.unread && (
                <span
                  className="size-1.5 shrink-0 rounded-full bg-primary"
                  aria-label="Unread"
                />
              )}
              <span className="max-w-[45%] shrink-0 truncate text-[11px] text-muted-foreground/50">
                {item.worktreeName}
              </span>
            </button>
          ))
        ))}
    </div>
  )
}

export const InstanceSessionsSection = memo(InstanceSessionsSectionImpl)
