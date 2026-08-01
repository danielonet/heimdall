import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

function formatTime(iso) {
  return new Date(iso).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
}

export function PortHistorySparkline({ history }) {
  const data = (history || [])
    .filter((s) => s.time)
    .slice()
    .reverse() // API returns newest-first; charts read left-to-right chronologically
    .map((s) => ({ time: formatTime(s.time), sent: s.bytes_sent_delta ?? 0, recv: s.bytes_recv_delta ?? 0 }))

  if (data.length === 0) {
    return <div className="text-[10px] text-text-muted">No history yet.</div>
  }

  return (
    <ResponsiveContainer width="100%" height={100}>
      <LineChart data={data} margin={{ left: 0, right: 8, top: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
        <XAxis dataKey="time" tick={{ fontSize: 8, fill: 'var(--color-text-muted)' }} />
        <YAxis tick={{ fontSize: 8, fill: 'var(--color-text-muted)' }} width={30} />
        <Tooltip contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', fontSize: 10 }} />
        <Line type="monotone" dataKey="sent" name="Sent" stroke="var(--color-accent-blue)" dot={false} strokeWidth={1.5} />
        <Line type="monotone" dataKey="recv" name="Received" stroke="var(--color-accent-green)" dot={false} strokeWidth={1.5} />
      </LineChart>
    </ResponsiveContainer>
  )
}
