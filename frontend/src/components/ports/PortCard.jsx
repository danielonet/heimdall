import { useState } from 'react'
import { Badge } from '../Badge'
import { usePortHistory } from '../../hooks/usePortHistory'
import { PortHistorySparkline } from './PortHistorySparkline'

function formatBytes(bytes) {
  if (bytes == null) return '—'
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

export function PortCard({ port }) {
  const [expanded, setExpanded] = useState(false)
  const { data: history } = usePortHistory(port.port_alias, { enabled: expanded })
  const isUp = port.status === 'UP'

  return (
    <div className="border border-border bg-surface p-4">
      <div className="mb-2 flex items-center justify-between">
        <span className="font-heading text-sm font-semibold text-text-primary">{port.port_alias}</span>
        <Badge variant={isUp ? 'success' : 'info'}>{port.status || '—'}</Badge>
      </div>

      <div className="mb-2 text-[10px] text-text-secondary">
        {port.link_speed_mbps != null ? `${port.link_speed_mbps} Mbps` : 'No link'}
      </div>

      <div className="mb-2 flex items-center gap-3 text-[10px] text-accent-blue">
        <span>↑ {formatBytes(port.bytes_sent_delta)}</span>
        <span>↓ {formatBytes(port.bytes_recv_delta)}</span>
      </div>

      <div className="mb-3 text-[9px] text-text-muted">
        {port.errors_recv || 0} errors · {port.discards_recv || 0} discards
      </div>

      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="w-full border border-border py-1 text-[9px] tracking-wider text-text-muted transition-colors hover:text-text-secondary"
      >
        {expanded ? 'SHOW LESS' : 'SHOW MORE'}
      </button>

      {expanded && (
        <div className="mt-3">
          <PortHistorySparkline history={history} />
          <table className="mt-2 w-full text-[9px] text-text-secondary">
            <tbody>
              <tr>
                <td className="py-0.5 text-text-muted">Last change</td>
                <td className="py-0.5 text-right">
                  {port.last_change_secs != null ? `${port.last_change_secs}s ago` : '—'}
                </td>
              </tr>
              <tr>
                <td className="py-0.5 text-text-muted">Broadcast</td>
                <td className="py-0.5 text-right">{port.broadcast_recv ?? '—'}</td>
              </tr>
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
