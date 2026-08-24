import { useMemo } from 'react'
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

export function TrafficBarChart({ devices }) {
  // Memoized so this filter/map/sort/slice chain only re-runs when devices
  // itself actually changes (a 15s poll), not on every unrelated re-render
  // of an ancestor — see DesktopShell's Clock fix for why that distinction
  // mattered here (this chart used to re-run 3600x/hour for no reason).
  const data = useMemo(
    () =>
      (devices || [])
        .filter((d) => d.latest_traffic?.throughput_up_kbps != null)
        .map((d) => ({ name: d.hostname || d.mac_address, up: d.latest_traffic.throughput_up_kbps }))
        .sort((a, b) => b.up - a.up)
        .slice(0, 6),
    [devices],
  )

  if (data.length === 0) {
    return <div className="text-[10px] text-text-muted">No traffic data yet.</div>
  }

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" horizontal={false} />
        <XAxis type="number" tick={{ fontSize: 9, fill: 'var(--color-text-muted)' }} />
        <YAxis type="category" dataKey="name" width={90} tick={{ fontSize: 9, fill: 'var(--color-text-muted)' }} />
        <Tooltip
          contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', fontSize: 11 }}
          formatter={(value) => [`${value} kbps`, 'Upload']}
        />
        <Bar dataKey="up" fill="var(--color-accent-blue)" />
      </BarChart>
    </ResponsiveContainer>
  )
}
