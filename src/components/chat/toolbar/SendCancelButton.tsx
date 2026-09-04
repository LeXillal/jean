import { ArrowUp, CornerDownLeft, Send, Square } from 'lucide-react'
import { getModifierSymbol, isClientMacOS } from '@/lib/platform'
import { cn } from '@/lib/utils'
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip'
import { useIsMobile } from '@/hooks/use-mobile'

interface SendCancelButtonProps {
  isSending: boolean
  canSend: boolean
  /** When true, the secondary action steers into the running turn instead of queueing. */
  willSteer?: boolean
  /** When true, steering requires the primary modifier plus Enter. */
  steerWithModifier?: boolean
  queuedMessageCount?: number
  onCancel: () => void
}

/** Shared shape for every round icon action in the composer. */
const iconButtonBase =
  'flex size-8 shrink-0 items-center justify-center rounded-full transition-colors disabled:pointer-events-none disabled:opacity-50'

export function SendCancelButton({
  isSending,
  canSend,
  willSteer = false,
  steerWithModifier = false,
  queuedMessageCount,
  onCancel,
}: SendCancelButtonProps) {
  const isMobile = useIsMobile()

  const cancelShortcut = isClientMacOS
    ? `${getModifierSymbol()}+Option+Backspace`
    : 'Ctrl+Alt+Backspace'

  if (isSending) {
    const skip = Boolean(queuedMessageCount)
    const cancelButton = (
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            type="button"
            onClick={onCancel}
            aria-label={skip ? 'Skip to Next' : 'Cancel'}
            className={cn(
              iconButtonBase,
              'group relative bg-muted text-foreground hover:bg-destructive/10 hover:text-destructive'
            )}
          >
            <span
              aria-hidden
              className="pointer-events-none absolute -inset-0.5 animate-spin rounded-full border-2 border-transparent border-t-primary/70 [animation-duration:1.2s] group-hover:border-t-destructive/70"
            />
            <Square className="size-3.5 fill-current transition-transform duration-200 ease-out group-hover:scale-90" />
          </button>
        </TooltipTrigger>
        <TooltipContent>
          {skip
            ? `Skip to next queued message (${cancelShortcut})`
            : `Cancel (${cancelShortcut})`}
        </TooltipContent>
      </Tooltip>
    )

    if (canSend) {
      const actionLabel = willSteer ? 'Steer' : 'Queue'
      const actionShortcut = steerWithModifier
        ? `${getModifierSymbol()}+Enter`
        : 'Enter'
      const actionTooltip = willSteer
        ? isMobile
          ? 'Steer into running turn'
          : `Steer into running turn (${actionShortcut})`
        : isMobile
          ? 'Queue message'
          : 'Queue message (Enter)'

      return (
        <div className="flex items-center gap-0.5">
          {cancelButton}
          <div className="mx-0.5 h-4 w-px shrink-0 bg-border/50" />
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                type="submit"
                aria-label={actionLabel}
                className={cn(
                  iconButtonBase,
                  'text-muted-foreground hover:bg-muted/80 hover:text-foreground'
                )}
              >
                {willSteer ? (
                  <CornerDownLeft className="size-4" />
                ) : (
                  <ArrowUp className="size-4" />
                )}
              </button>
            </TooltipTrigger>
            <TooltipContent>{actionTooltip}</TooltipContent>
          </Tooltip>
        </div>
      )
    }

    return cancelButton
  }

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <button
          type="submit"
          disabled={!canSend}
          aria-label="Send"
          className={cn(
            iconButtonBase,
            'group',
            canSend
              ? 'bg-primary text-primary-foreground hover:bg-primary/90'
              : 'bg-muted text-muted-foreground'
          )}
        >
          <Send
            className={cn(
              'size-4 transition-transform duration-200 ease-out',
              canSend &&
                'group-hover:-translate-y-px group-hover:translate-x-px group-hover:-rotate-12 group-active:-translate-y-1 group-active:translate-x-1 group-active:-rotate-45'
            )}
          />
        </button>
      </TooltipTrigger>
      <TooltipContent>
        {isMobile ? 'Send message' : 'Send message (Enter)'}
      </TooltipContent>
    </Tooltip>
  )
}
