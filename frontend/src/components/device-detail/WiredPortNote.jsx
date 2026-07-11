import { Link } from 'react-router-dom'

// See docs/router/wired-monitoring-caveat.md — the router only exposes
// port-level counters for wired devices, so this device's own MAC never
// accumulates traffic_samples; the charts above will always be empty for it.
export function WiredPortNote({ portAlias }) {
  return (
    <div className="border border-accent-amber/30 bg-accent-amber/5 p-3 text-[10px] text-text-secondary">
      This is a wired device — the router only measures traffic per switch
      port, not per device, so no individual traffic history is available.
      {portAlias && (
        <>
          {' '}
          See port{' '}
          <Link to="/ports" className="text-accent-amber underline">
            {portAlias}
          </Link>{' '}
          for the aggregate figures shared with other devices on that port.
        </>
      )}
    </div>
  )
}
