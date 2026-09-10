import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { formatBytes } from '../../lib/format'

// Same recharts shape as AlertHistogram/TrafficBarChart — a real chart
// component native to the app's own theme, not a port of the digest
// email's table-of-colored-cells trick (that one exists purely because
// email clients can't run arbitrary CSS/JS; a webpage has no such limit).
export function ReportBandwidthChart({ hourlyBandwidth }) {
  if (!hourlyBandwidth || hourlyBandwidth.length === 0) {
    return <div className="text-[10px] text-text-muted">No WAN bandwidth data for this window.</div>
  }

  const data = hourlyBandwidth.map((h) => ({
    hour: new Date(h.hour).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit' }),
    bytes: Number(h.total_bytes),
  }))

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data} margin={{ left: 8, right: 8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
        <XAxis
          dataKey="hour"
          tick={{ fontSize: 8, fill: 'var(--color-text-muted)' }}
          interval="preserveStartEnd"
          minTickGap={24}
        />
        <YAxis
          tick={{ fontSize: 9, fill: 'var(--color-text-muted)' }}
          width={48}
          tickFormatter={(v) => formatBytes(v)}
        />
        <Tooltip
          contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', fontSize: 11 }}
          formatter={(value) => [formatBytes(value), 'Total']}
        />
        <Bar dataKey="bytes" fill="var(--color-accent-green)" />
      </BarChart>
    </ResponsiveContainer>
  )
}
