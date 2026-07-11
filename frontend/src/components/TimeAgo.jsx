import { useEffect, useState } from 'react'

function relativeTime(iso) {
  if (!iso) return '—'
  const diffS = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diffS < 10) return 'just now'
  if (diffS < 60) return `${diffS}s ago`
  const diffM = Math.floor(diffS / 60)
  if (diffM < 60) return `${diffM}m ago`
  const diffH = Math.floor(diffM / 60)
  if (diffH < 24) return `${diffH}h ago`
  return `${Math.floor(diffH / 24)}d ago`
}

export function TimeAgo({ iso }) {
  // Forces a re-render every 15s so "3m ago" keeps advancing without a refetch.
  const [, setTick] = useState(0)
  useEffect(() => {
    const id = setInterval(() => setTick((n) => n + 1), 15000)
    return () => clearInterval(id)
  }, [])
  return <span>{relativeTime(iso)}</span>
}
