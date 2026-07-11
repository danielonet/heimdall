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
        <CartesianGrid strokeDasharray="3 3" stroke="#1a2535" />
        <XAxis dataKey="time" tick={{ fontSize: 9, fill: '#5a7090' }} />
        <YAxis tick={{ fontSize: 9, fill: '#5a7090' }} width={30} domain={[-1, 1]} />
        <Tooltip contentStyle={{ background: '#0a0f18', border: '1px solid rgba(0,220,140,0.2)', fontSize: 11 }} />
        <Line type="monotone" dataKey="score" stroke="#f0a030" dot={false} strokeWidth={1.5} />
      </LineChart>
    </ResponsiveContainer>
  )
}
