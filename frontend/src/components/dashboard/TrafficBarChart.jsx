import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'

export function TrafficBarChart({ devices }) {
  const data = (devices || [])
    .filter((d) => d.latest_traffic?.throughput_up_kbps != null)
    .map((d) => ({ name: d.hostname || d.mac_address, up: d.latest_traffic.throughput_up_kbps }))
    .sort((a, b) => b.up - a.up)
    .slice(0, 6)

  if (data.length === 0) {
    return <div className="text-[10px] text-text-muted">No traffic data yet.</div>
  }

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 8 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#1a2535" horizontal={false} />
        <XAxis type="number" tick={{ fontSize: 9, fill: '#5a7090' }} />
        <YAxis type="category" dataKey="name" width={90} tick={{ fontSize: 9, fill: '#5a7090' }} />
        <Tooltip
          contentStyle={{ background: '#0a0f18', border: '1px solid rgba(0,220,140,0.2)', fontSize: 11 }}
          formatter={(value) => [`${value} kbps`, 'Upload']}
        />
        <Bar dataKey="up" fill="#00aaff" />
      </BarChart>
    </ResponsiveContainer>
  )
}
