// Shared AP-alias grouping logic for the Devices page's "group by AP" view
// (Desktop table + Mobile cards both use this so the ordering/labeling stays
// identical between layouts).
const AP_ORDER = ['PRIV0', 'VID1', 'GUEST2G', 'GUEST5G', 'AP_BACKHAUL']
export const WIRED_AP_GROUP = 'WIRED'
export const UNASSOCIATED_AP_GROUP = 'NOT ASSOCIATED'

// Wired devices never carry an ap_alias (see docs/router/wired-monitoring-caveat.md)
// and a WiFi device the router hasn't associated with an AP yet also has none
// — each gets its own catch-all group rather than being silently dropped
// from the grouped view.
export function apGroupKey(device) {
  if (device.ap_alias) return device.ap_alias
  return device.interface_name === 'Ethernet' ? WIRED_AP_GROUP : UNASSOCIATED_AP_GROUP
}

// Mirrors the same GUEST-prefix convention already used to badge guest
// devices elsewhere (DesktopDevicesList's TYPE column, DeviceHeader.jsx).
export function isGuestApGroup(label) {
  return label.startsWith('GUEST')
}

// Buckets `items` by apGroupKey(getDevice(item)) and returns [label, items[]]
// pairs in a stable, human-meaningful order (private APs, then guest APs,
// then wired, then unassociated) rather than insertion/Map order.
export function groupByAp(items, getDevice = (item) => item) {
  const buckets = new Map()
  for (const item of items) {
    const key = apGroupKey(getDevice(item))
    if (!buckets.has(key)) buckets.set(key, [])
    buckets.get(key).push(item)
  }

  const order = [...AP_ORDER, WIRED_AP_GROUP, UNASSOCIATED_AP_GROUP]
  return [...buckets.entries()].sort(([a], [b]) => {
    const ai = order.indexOf(a)
    const bi = order.indexOf(b)
    return (ai === -1 ? order.length : ai) - (bi === -1 ? order.length : bi)
  })
}
