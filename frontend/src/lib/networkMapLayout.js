// Positions devices on the Network Map's radial layout: angle encodes AP
// segment (reusing apGroups.js — the same grouping the Devices page's
// "GROUP BY AP" toggle uses), distance from center encodes urgency.
import { apGroupKey, groupByAp } from './apGroups'
import { isDeviceOnline } from './deviceFilters'

export const MAP_CENTER = { x: 500, y: 380 }
export const TIER_RADIUS = { THREAT: 130, WATCH: 230, CALM: 330 }
export const OUTER_RADIUS = 370

const TIER_ORDER = ['THREAT', 'WATCH', 'CALM']
const SEVERITY_RANK = { CRITICAL: 3, WARNING: 2, INFO: 1 }

// Past this many devices in one (sector, tier) bucket, a single ring of
// evenly-spaced angles starts crowding — split the bucket into two
// concentric sub-rings instead. See docs/network-map-plan.md.
const DENSE_BUCKET_THRESHOLD = 14
const SUB_RING_OFFSET = 16

// Worst *unresolved* alert severity per device — resolved alerts shouldn't
// keep pulling a device toward the THREAT ring.
function worstOpenSeverityByMac(alertGroups) {
  const map = new Map()
  for (const g of alertGroups) {
    if (!g.device_mac || g.unresolved_count === 0) continue
    const rank = SEVERITY_RANK[g.severity] || 0
    const prev = map.get(g.device_mac)
    if (!prev || rank > prev.rank) map.set(g.device_mac, { severity: g.severity, rank })
  }
  return map
}

function tierFor(device, worstSeverity) {
  if (worstSeverity === 'CRITICAL') return 'THREAT'
  if (worstSeverity === 'WARNING') return 'WATCH'
  if (device.is_quarantined) return 'WATCH'
  if (!device.is_trusted && isDeviceOnline(device)) return 'WATCH'
  return 'CALM'
}

function statusFor(device, worstSeverity) {
  if (device.is_blocked) return 'blocked'
  if (device.is_quarantined) return 'quarantined'
  if (worstSeverity === 'CRITICAL') return 'critical'
  if (worstSeverity === 'WARNING') return 'warning'
  if (isDeviceOnline(device)) return 'online'
  return 'offline'
}

// Deterministic per-device hash so a node's jitter offset is stable across
// refetches (every 15s) instead of visibly drifting each poll.
function hashMac(mac) {
  let h = 0
  for (let i = 0; i < mac.length; i++) h = (h * 31 + mac.charCodeAt(i)) >>> 0
  return h
}

function placeInBucket(items, sectorStart, sectorSpan, baseRadius) {
  const dense = items.length > DENSE_BUCKET_THRESHOLD
  const rings = dense
    ? [
        { list: items.filter((_, i) => i % 2 === 0), radius: baseRadius - SUB_RING_OFFSET },
        { list: items.filter((_, i) => i % 2 === 1), radius: baseRadius + SUB_RING_OFFSET },
      ]
    : [{ list: items, radius: baseRadius }]

  const placed = []
  for (const { list, radius } of rings) {
    list.forEach((item, i) => {
      const slot = (i + 0.5) / list.length
      const angle = sectorStart + slot * sectorSpan
      const jitter = (hashMac(item.device.mac_address) % 17) - 8 // -8..8px, stable per device
      const r = radius + jitter
      placed.push({
        mac: item.device.mac_address,
        hostname: item.device.hostname,
        nickname: item.device.nickname,
        ip_address: item.device.ip_address,
        sector: item.sector,
        tier: item.tier,
        status: item.status,
        angle,
        x: MAP_CENTER.x + Math.cos(angle) * r,
        y: MAP_CENTER.y + Math.sin(angle) * r,
      })
    })
  }
  return placed
}

/**
 * Computes {sector, tier, status, x, y} for every device, ready to render as
 * an SVG node. `alertGroups` should be the unresolved-alerts view (e.g.
 * useAlertGroups({ resolved: 'false' })) so severity reflects open alerts only.
 */
export function computeNodeLayout(devices, alertGroups) {
  const severityByMac = worstOpenSeverityByMac(alertGroups || [])
  const withMeta = devices.map((device) => {
    const worst = severityByMac.get(device.mac_address)?.severity
    return { device, sector: apGroupKey(device), tier: tierFor(device, worst), status: statusFor(device, worst) }
  })

  const sectorGroups = groupByAp(withMeta, (m) => m.device)
  const sectorCount = sectorGroups.length || 1
  const sectorSpan = (2 * Math.PI) / sectorCount

  const sectors = []
  const nodes = []
  sectorGroups.forEach(([label, items], sectorIndex) => {
    const sectorStart = -Math.PI / 2 + sectorIndex * sectorSpan
    sectors.push({ label, startAngle: sectorStart, midAngle: sectorStart + sectorSpan / 2 })

    const byTier = new Map(TIER_ORDER.map((t) => [t, []]))
    for (const item of items) byTier.get(item.tier).push(item)

    for (const tier of TIER_ORDER) {
      const bucket = byTier.get(tier)
      if (bucket.length === 0) continue
      nodes.push(...placeInBucket(bucket, sectorStart, sectorSpan, TIER_RADIUS[tier]))
    }
  })

  return { nodes, sectors, sectorSpan }
}
