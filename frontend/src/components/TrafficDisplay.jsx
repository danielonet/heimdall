import { ThroughputArrows } from './ThroughputArrows'
import { Badge } from './Badge'

// Must respect TrafficGranularity — see docs/router/wired-monitoring-caveat.md.
// Wired devices only get PHY-port aggregate counters, never per-device ones.
export function TrafficDisplay({ sample }) {
  if (!sample) return <span className="text-text-muted">—</span>

  return (
    <span className="inline-flex items-center gap-1.5">
      <ThroughputArrows upKbps={sample.throughput_up_kbps} downKbps={sample.throughput_dn_kbps} />
      {sample.granularity === 'per_port' && (
        <Badge variant="warning" title="Port aggregate — not measured per-device">
          PORT TOTAL
        </Badge>
      )}
    </span>
  )
}
