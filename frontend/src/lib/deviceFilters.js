// "Online" isn't a field the REST API returns (only the live socket payload
// has is_online, and only once a device has actually emitted an update) — so
// it's derived here from last_seen recency instead. 60s is a generous multiple
// of the default 15s poll interval, not a backend-declared threshold.
const ONLINE_THRESHOLD_MS = 60_000

export function isDeviceOnline(device) {
  if (!device.last_seen) return false
  return Date.now() - new Date(device.last_seen).getTime() < ONLINE_THRESHOLD_MS
}

export function filterDevices(devices, { search, connectivity, network, trust }) {
  const q = search.trim().toLowerCase()

  return devices.filter((d) => {
    if (q) {
      const haystack = `${d.hostname || ''} ${d.ip_address || ''} ${d.mac_address}`.toLowerCase()
      if (!haystack.includes(q)) return false
    }

    if (connectivity === 'online' && !isDeviceOnline(d)) return false
    if (connectivity === 'offline' && isDeviceOnline(d)) return false

    if (network === 'wifi' && d.interface_name !== 'WiFi') return false
    if (network === 'wired' && d.interface_name !== 'Ethernet') return false

    if (trust === 'trusted' && !d.is_trusted) return false
    if (trust === 'suspect' && d.is_trusted) return false

    return true
  })
}
