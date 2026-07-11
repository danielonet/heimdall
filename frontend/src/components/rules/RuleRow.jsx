import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../../lib/api'
import { Badge } from '../Badge'

const ACTION_VARIANTS = {
  BLOCK_DEVICE: 'danger',
  ALERT: 'warning',
  NOTIFY: 'info',
  TAG_DEVICE: 'success',
  RATE_LIMIT: 'info',
}

export function RuleRow({ rule, onEdit }) {
  const qc = useQueryClient()

  const toggle = useMutation({
    mutationFn: (enabled) => apiJson(`/rules/${rule.id}`, { method: 'PUT', body: JSON.stringify({ enabled }) }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })

  const remove = useMutation({
    mutationFn: () => apiJson(`/rules/${rule.id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['rules'] }),
  })

  const trigger = rule.condition_json.trigger || 'TRAFFIC_SAMPLE'

  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-border/50 p-3 last:border-none">
      <div className="min-w-0 flex-1">
        <div className="text-[11px] text-text-primary">{rule.name}</div>
        <div className="truncate text-[9px] text-text-muted">
          {trigger} · {rule.condition_json.field} {rule.condition_json.op} {JSON.stringify(rule.condition_json.value)}
          {rule.condition_json.window_polls > 1 && ` (×${rule.condition_json.window_polls} polls)`}
        </div>
      </div>
      <Badge variant={ACTION_VARIANTS[rule.action_json.type] || 'info'}>{rule.action_json.type}</Badge>
      <button
        type="button"
        disabled={toggle.isPending}
        onClick={() => toggle.mutate(!rule.enabled)}
        className={`border px-2 py-1 text-[9px] tracking-wider transition-colors ${
          rule.enabled
            ? 'border-accent-green/40 bg-accent-green/10 text-accent-green'
            : 'border-border text-text-muted'
        }`}
      >
        {rule.enabled ? 'ENABLED' : 'DISABLED'}
      </button>
      <button
        type="button"
        onClick={() => onEdit(rule)}
        className="border border-border px-2 py-1 text-[9px] tracking-wider text-text-muted transition-colors hover:text-text-secondary"
      >
        EDIT
      </button>
      <button
        type="button"
        disabled={remove.isPending}
        onClick={() => {
          if (confirm(`Delete rule "${rule.name}"?`)) remove.mutate()
        }}
        className="border border-accent-red/30 bg-accent-red/5 px-2 py-1 text-[9px] tracking-wider text-accent-red transition-colors hover:bg-accent-red/20"
      >
        DELETE
      </button>
    </div>
  )
}
