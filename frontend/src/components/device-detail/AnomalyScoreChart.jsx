import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

function formatTime(iso) {
  const d = new Date(iso)
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
}

export function AnomalyScoreChart({ history }) {
  const data = (history || [])
    .filter((s) => s.time && s.anomaly_score != null)
    .slice()
    .reverse()
    .map((s) => ({ time: formatTime(s.time), score: s.anomaly_score }))

  if (data.length === 0) {
    return (
      <div className="text-[10px] text-text-muted">
        No anomaly scores yet — the ML model bootstraps after enough samples.
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={140}>
      <LineChart data={data} margin={{ left: 0, right: 8, top: 8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" />
        <XAxis dataKey="time" tick={{ fontSize: 9, fill: 'var(--color-text-muted)' }} />
        <YAxis tick={{ fontSize: 9, fill: 'var(--color-text-muted)' }} width={30} domain={[-1, 1]} />
        <Tooltip contentStyle={{ background: 'var(--color-surface)', border: '1px solid var(--color-border)', fontSize: 11 }} />
        <Line type="monotone" dataKey="score" stroke="var(--color-accent-amber)" dot={false} strokeWidth={1.5} />
      </LineChart>
    </ResponsiveContainer>
  )
}
