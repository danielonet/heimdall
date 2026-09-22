import { useEffect, useState } from 'react'

// A ticking "now" for views that need to re-evaluate a time-based rule (e.g.
// "has it been a minute") even between data refetches — react-query only
// re-renders when the fetched data itself changes, and time can cross a
// threshold with no other row's data changing in that same window. Shared
// by the WIFI tab and the Network Map, both of which use it to age out
// stale WiFi sightings — see lib/wifiSightings.js.
export function useNowTick(intervalMs = 5000) {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs)
    return () => clearInterval(id)
  }, [intervalMs])
  return now
}
