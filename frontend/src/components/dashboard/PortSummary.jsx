import { Badge } from '../Badge'

export function PortSummary({ ports }) {
  if (!ports?.length) return <div className="text-[10px] text-text-muted">No port data.</div>

  return (
    <div className="grid grid-cols-5 gap-2">
      {ports.map((p) => (
        <div key={p.port_alias} className="border border-border bg-surface p-2 text-center">
          <div className="mb-1 text-[9px] tracking-wide text-text-muted">{p.port_alias}</div>
          <Badge variant={p.status === 'UP' ? 'success' : 'info'}>{p.status || '—'}</Badge>
          {p.link_speed_mbps != null && (
            <div className="mt-1 text-[9px] text-text-secondary">{p.link_speed_mbps} Mbps</div>
          )}
        </div>
      ))}
    </div>
  )
}
