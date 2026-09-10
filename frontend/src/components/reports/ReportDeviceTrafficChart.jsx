import { useMemo } from 'react'
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { formatBytes } from '../../lib/format'

const MAX_BARS = 12

// Untrusted gets flagged red — same accent-red token every other danger/
// warning surface in the app uses (Badge's 'danger' variant, PurgeDatabase-
// Section's border, etc.), so it stays correct across the amber/slate
// palettes and both themes automatically rather than a hardcoded hex.
const TRUSTED_COLOR = 'var(--color-accent-green)'
const UNTRUSTED_COLOR = 'var(--color-accent-red)'

/** Requested directly: the device-traffic bar graph colors an untrusted
 * device's bar red instead of the normal trusted-device color, so it reads
 * at a glance without needing the table's TRUSTED column. Same recharts
 * shape as TrafficBarChart (Dashboard) — horizontal bars, device names on
 * the category axis. */
export function ReportDeviceTrafficChart({ traffic }) {
  const data = useMemo(
    () =>
      (traffic || [])
        .map((t) => ({
          name: t.device_label,
          total: t.upload_bytes + t.download_bytes,
          isTrusted: t.is_trusted,
        }))
        .sort((a, b) => b.total - a.total)
        .slice(0, MAX_BARS),
    [traffic],
  )

  if (data.length === 0) {
    return <div className="text-[10px] text-text-muted">No per-device traffic in this window.</div>
  }

  return (
    <ResponsiveContainer width="100%" height={Math.max(120, data.length * 24)}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" horizontal={false} />
        <XAxis
          type="number"
          tick={{ fontSize: 9, fill: 'var(--color-text-muted)' }}
          tickFormatter={(v) => formatBytes(v)}
        />
        <YAxis
          type="category"
          dataKey="name"
          width={110}
          tick={{ fontSize: 9, fill: 'var(--color-text-muted)' }}
        />
        <Tooltip
          contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', fontSize: 11 }}
          formatter={(value, _name, item) => [
            `${formatBytes(value)} — ${item.payload.isTrusted ? 'trusted' : 'UNTRUSTED'}`,
            'Total',
          ]}
        />
        <Bar dataKey="total">
          {data.map((d) => (
            <Cell key={d.name} fill={d.isTrusted ? TRUSTED_COLOR : UNTRUSTED_COLOR} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}
