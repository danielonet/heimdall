import { formatBitRate } from '../../lib/format'
import { useSwitchPorts } from '../../hooks/useSwitches'

const CELL = 'px-2 py-1 text-left align-top'

// The latest reading of each port of one switch. "Up" and "down" are from the point of view of whatever is
// plugged into the port, so a device's download is what the switch sent out of its port.
export function SwitchPortsTable({ id }) {
  const { data: ports, isLoading, isError, error } = useSwitchPorts(id, true)

  if (isLoading) return <div className="mt-2 text-[10px] text-text-muted">Loading…</div>
  if (isError) return <div className="mt-2 text-[10px] text-accent-red">{error.message}</div>
  if (!ports?.length) {
    return (
      <div className="mt-2 text-[10px] text-text-muted">
        No readings yet. The first poll only sets a baseline; ports appear after the second one.
      </div>
    )
  }

  return (
    <div className="mt-2 overflow-x-auto">
      <table className="w-full min-w-[34rem] text-[10px] text-text-primary">
        <thead>
          <tr className="text-[8px] tracking-wider text-text-muted">
            <th className={CELL}>PORT</th>
            <th className={CELL}>LINK</th>
            <th className={CELL}>SPEED</th>
            <th className={CELL}>DEVICE</th>
            <th className={CELL}>↓ DOWN</th>
            <th className={CELL}>↑ UP</th>
          </tr>
        </thead>
        <tbody>
          {ports.map((p) => (
            <tr key={p.port} className="border-t border-border/40">
              <td className={CELL}>{p.port}</td>
              <td className={CELL + (p.link_up ? ' text-accent-green' : ' text-text-muted')}>{p.link_up ? 'UP' : 'DOWN'}</td>
              <td className={CELL}>{p.speed_mbps ? `${p.speed_mbps} Mb/s` : '—'}</td>
              <td className={CELL}>
                {p.attributed_mac ? (
                  p.device_name || p.attributed_mac
                ) : p.macs > 1 ? (
                  <span className="text-text-secondary" title="Shared by several devices: the figures are a port total, not any one device's">
                    {p.macs} devices · port total
                  </span>
                ) : (
                  <span className="text-text-muted">{p.link_up ? 'no device seen' : '—'}</span>
                )}
              </td>
              <td className={CELL}>{formatBitRate(p.throughput_out_kbps)}</td>
              <td className={CELL}>{formatBitRate(p.throughput_in_kbps)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <p className="mt-1 text-[9px] leading-relaxed text-text-muted">
        Down and up are from the connected device’s side. A port with exactly one device is that device’s own
        traffic; a port shared by several (an uplink, an access point) is a total and is not credited to any one.
      </p>
    </div>
  )
}
