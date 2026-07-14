// WiFi signal strength as 5 ascending bars, mapped from dBm using the rough
// excellent/good/fair/weak/poor thresholds most OS Wi-Fi indicators use.
const THRESHOLDS = [
  { min: -50, bars: 5, color: 'bg-accent-green' },
  { min: -60, bars: 4, color: 'bg-accent-green' },
  { min: -67, bars: 3, color: 'bg-accent-amber' },
  { min: -70, bars: 2, color: 'bg-accent-amber' },
  { min: -80, bars: 1, color: 'bg-accent-red' },
]

function barsFor(dbm) {
  if (!dbm) return { bars: 0, color: 'bg-text-muted' }
  const match = THRESHOLDS.find((t) => dbm >= t.min)
  return match || { bars: 0, color: 'bg-accent-red' }
}

export function SignalBars({ dbm }) {
  const { bars, color } = barsFor(dbm)
  return (
    <div
      className="inline-flex items-end gap-[2px]"
      title={dbm ? `${dbm} dBm` : 'No signal data'}
    >
      {[1, 2, 3, 4, 5].map((i) => (
        <span
          key={i}
          className={`w-[3px] ${i <= bars ? color : 'bg-border'}`}
          style={{ height: `${2 + i * 2}px` }}
        />
      ))}
    </div>
  )
}
