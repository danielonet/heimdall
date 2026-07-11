import { TimeAgo } from '../TimeAgo'
import { Badge } from '../Badge'

export function OpenPortsPanel({ nmapProfile }) {
  if (!nmapProfile) {
    return <div className="text-[10px] text-text-muted">No Nmap scan yet — runs nightly (NMAP_SCAN_CRON).</div>
  }

  const ports = nmapProfile.ports || []

  return (
    <div>
      <div className="mb-2 flex items-center justify-between text-[10px] text-text-secondary">
        <span>
          OS guess: <span className="text-text-primary">{nmapProfile.os || 'Unknown'}</span>
        </span>
        <span className="text-text-muted">
          scanned <TimeAgo iso={nmapProfile.scanned_at} />
        </span>
      </div>

      {ports.length === 0 ? (
        <div className="text-[10px] text-text-muted">No open ports found.</div>
      ) : (
        <table className="w-full text-[10px]">
          <thead>
            <tr className="border-b border-border text-left text-[9px] tracking-wider text-text-muted">
              <th className="py-1 pr-2">PORT</th>
              <th className="py-1 pr-2">PROTO</th>
              <th className="py-1 pr-2">SERVICE</th>
              <th className="py-1 pr-2">VERSION</th>
              <th className="py-1">STATE</th>
            </tr>
          </thead>
          <tbody>
            {ports.map((p) => (
              <tr key={`${p.port}/${p.protocol}`} className="border-b border-border/50 last:border-none">
                <td className="py-1 pr-2 text-text-primary">{p.port}</td>
                <td className="py-1 pr-2 text-text-secondary">{p.protocol}</td>
                <td className="py-1 pr-2 text-text-secondary">{p.service || '—'}</td>
                <td className="py-1 pr-2 text-text-muted">{p.version || '—'}</td>
                <td className="py-1">
                  <Badge variant={p.state === 'open' ? 'success' : 'info'}>{p.state}</Badge>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
