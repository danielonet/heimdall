// is_online reflects the router's own Active flag for this device as of the
// most recent poll (see sentinel/scheduler/jobs.py:_upsert_devices) — not a
// last_seen-recency guess. A device can sit in the registry indefinitely
// without ever being active again (e.g. a reserved DHCP pool slot), so
// recency alone was never a reliable proxy for "currently connected".
export function isDeviceOnline(device) {
  return Boolean(device.is_online)
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
