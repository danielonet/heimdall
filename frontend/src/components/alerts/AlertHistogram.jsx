import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

const HOUR_MS = 3600_000

export function AlertHistogram({ alerts }) {
  const now = Date.now()
  const buckets = []
  for (let i = 23; i >= 0; i--) {
    const bucketStart = now - i * HOUR_MS
    buckets.push({ hour: `${new Date(bucketStart).getHours()}:00`, start: bucketStart, count: 0 })
  }

  for (const a of alerts) {
    if (!a.created_at) continue
    const t = new Date(a.created_at).getTime()
    const age = now - t
    if (age < 0 || age > 24 * HOUR_MS) continue
    const bucket = buckets[23 - Math.floor(age / HOUR_MS)]
    if (bucket) bucket.count += 1
  }

  return (
    <ResponsiveContainer width="100%" height={120}>
      <BarChart data={buckets}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
        <XAxis dataKey="hour" tick={{ fontSize: 8, fill: 'var(--color-text-muted)' }} interval={3} />
        <YAxis tick={{ fontSize: 9, fill: 'var(--color-text-muted)' }} width={24} allowDecimals={false} />
        <Tooltip contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', fontSize: 11 }} />
        <Bar dataKey="count" fill="var(--color-accent-blue)" />
      </BarChart>
    </ResponsiveContainer>
  )
}
