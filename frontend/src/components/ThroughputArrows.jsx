function formatKbps(kbps) {
  if (kbps == null) return '—'
  if (kbps >= 1024) return `${(kbps / 1024).toFixed(1)} MB/s`
  return `${Math.round(kbps)} KB/s`
}

export function ThroughputArrows({ upKbps, downKbps }) {
  return (
    <span className="whitespace-nowrap text-accent-blue">
      ↑ {formatKbps(upKbps)} ↓ {formatKbps(downKbps)}
    </span>
  )
}
