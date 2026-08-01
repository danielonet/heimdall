import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

function formatTime(iso) {
  const d = new Date(iso)
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
}

export function TrafficTimelineChart({ history }) {
  const data = (history || [])
    .filter((s) => s.time)
    .slice()
    .reverse() // API returns newest-first; charts read left-to-right chronologically
    .map((s) => ({
      time: formatTime(s.time),
      up: s.throughput_up_kbps ?? 0,
      down: s.throughput_dn_kbps ?? 0,
    }))

  if (data.length === 0) {
    return <div className="text-[10px] text-text-muted">No per-device traffic history yet.</div>
  }

  return (
    <ResponsiveContainer width="100%" height={180}>
      <LineChart data={data} margin={{ left: 0, right: 8, top: 8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
        <XAxis dataKey="time" tick={{ fontSize: 9, fill: 'var(--color-text-muted)' }} />
        <YAxis tick={{ fontSize: 9, fill: 'var(--color-text-muted)' }} width={36} />
        <Tooltip contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', fontSize: 11 }} />
        <Line type="monotone" dataKey="up" name="Upload (Kbps)" stroke="var(--color-accent-blue)" dot={false} strokeWidth={1.5} />
        <Line type="monotone" dataKey="down" name="Download (Kbps)" stroke="var(--color-accent-green)" dot={false} strokeWidth={1.5} />
      </LineChart>
    </ResponsiveContainer>
  )
}
