import { useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { createPortal } from 'react-dom'
import { StatusDot } from '../StatusDot'
import { TimeAgo } from '../TimeAgo'
import { formatBytes } from '../../lib/format'
import { useServiceDetails } from '../../hooks/useServiceDetails'
import {
  CanaryIcon,
  CrosshairIcon,
  EyeIcon,
  FingerprintIcon,
  PostgresIcon,
  PulseIcon,
  RadarIcon,
  RedisIcon,
  RouterIcon,
  ShieldCheckIcon,
  ShieldIcon,
  SirenIcon,
  TagIcon,
  WifiIcon,
} from './ServiceIcons'

// Which alert_type(s) each service row can be blamed for — see
// ServiceStatusPanel's module docstring-equivalent comment below for the
// behavior rule. ARP_SPOOF's softer sibling IP_CONFLICT (raised instead
// when the "new" MAC is already trusted — see
// SentinelScheduler._persist_ip_conflict_alert) is deliberately excluded:
// it's INFO-severity and the backend's own comments call it "likely not an
// attack," so it shouldn't trigger a red alarm here. MALICIOUS_TRAFFIC_
// DESTINATION (from the spike-IP-enrichment job) has no row of its own and
// is attributed to zeek_beacon, the row backed by the same conn.log-based
// Zeek capability.
const ALERT_TYPES_BY_SERVICE = {
  arp_watch: new Set(['ARP_SPOOF']),
  dhcp_watch: new Set(['ROGUE_DHCP_SERVER']),
  fingerprint: new Set(['FINGERPRINT_MISMATCH']),
  nmap: new Set([
    'HIGH_RISK_PORT_OPENED', 'OS_FINGERPRINT_CONFLICT', 'VULNERABILITY_DETECTED', 'CREDENTIAL_EXPOSURE_DETECTED',
  ]),
  opencanary: new Set(['HONEYPOT_ACCESS']),
  zeek_dns: new Set(['DNS_MALICIOUS_QUERY']),
  zeek_beacon: new Set(['C2_BEACONING', 'MALICIOUS_TRAFFIC_DESTINATION']),
  clamav: new Set(['MALWARE_DETECTED']),
  suricata: new Set(['IDS_SIGNATURE_MATCH']),
  wifi_monitor: new Set(['ROGUE_AP']),
}

function Field({ label, value }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <dt className="flex-shrink-0 text-text-muted">{label}</dt>
      {/* break-words rather than truncate — VERSION strings (Postgres's in
       * particular, e.g. "PostgreSQL 16.14 (Ubuntu 16.14-...)") regularly
       * outrun this card's width, and wrapping to a second line beats
       * silently cutting off the packaging suffix. */}
      <dd className="break-words text-right text-text-primary">{value}</dd>
    </div>
  )
}

// Portaled to document.body and positioned from a captured getBoundingClientRect
// rather than a CSS-only absolute/group-hover popup — the panel's row list is
// overflow-y-auto, and a popup escaping to the left of a row would get clipped
// by that container's (CSS-spec-mandated) implicit overflow-x once overflow-y
// is anything but visible. position: fixed via a portal sidesteps that
// entirely, the same reason Modal.jsx already portals to document.body.
function ServiceHoverCard({ anchorRect, info }) {
  if (!anchorRect || !info) return null

  const style = {
    position: 'fixed',
    top: anchorRect.top + anchorRect.height / 2,
    left: anchorRect.left - 8,
    transform: 'translate(-100%, -50%)',
  }

  return createPortal(
    <div
      style={style}
      className="z-50 w-64 border border-border-active bg-surface-elevated p-3 text-[10px] leading-snug text-text-secondary shadow-[0_4px_16px_rgba(0,0,0,0.4)]"
    >
      <div className="mb-2 text-text-primary">{info.description}</div>
      <dl className="space-y-1">
        {info.version && <Field label="VERSION" value={info.version} />}
        {info.database_size_bytes != null && (
          <Field label="DATABASE SIZE" value={formatBytes(info.database_size_bytes)} />
        )}
        {info.used_memory_bytes != null && (
          <Field label="MEMORY USED" value={formatBytes(info.used_memory_bytes)} />
        )}
        <Field label="LAST ALERT" value={info.last_alert_at ? <TimeAgo iso={info.last_alert_at} /> : 'Never'} />
      </dl>
    </div>,
    document.body,
  )
}

function Row({ icon: Icon, label, ok, detail, alert, to, info }) {
  const navigate = useNavigate()
  const rowRef = useRef(null)
  const [hoverRect, setHoverRect] = useState(null)
  const clickable = alert && to
  const textClass = alert ? 'text-accent-red' : ok ? 'text-text-secondary' : 'text-text-muted'
  const iconClass = alert ? 'text-accent-red' : ok ? 'text-accent-green' : 'text-text-muted'
  const blink = alert ? 'animate-[pulse-live_2s_infinite]' : ''

  return (
    <div
      ref={rowRef}
      onClick={clickable ? () => navigate(to) : undefined}
      onMouseEnter={() => setHoverRect(rowRef.current?.getBoundingClientRect() ?? null)}
      onMouseLeave={() => setHoverRect(null)}
      className={`flex items-center justify-between border-b border-border/50 py-1.5 text-[10px] last:border-none ${
        clickable ? 'cursor-pointer hover:bg-border/20' : ''
      }`}
    >
      <span className={`flex items-center gap-1.5 ${textClass}`}>
        <Icon className={`h-3 w-3 flex-shrink-0 ${iconClass}`} />
        {label}
      </span>
      <span className={`flex items-center gap-1.5 ${textClass} ${blink}`}>
        <StatusDot variant={alert ? 'red' : ok ? 'green' : 'muted'} pulse={alert || ok} />
        {alert ? 'ALERT' : detail}
      </span>
      <ServiceHoverCard anchorRect={hoverRect} info={info} />
    </div>
  )
}

// One entry per service Heimdall can ever report on — `key` matches
// active_service_keys() in sentinel/deployment_tiers.py 1:1. Rows whose key
// isn't in health.active_services (e.g. Suricata on a MINIMAL install)
// don't render at all, rather than showing as permanently "OFF"/"PENDING"
// — those states are reserved for a service that IS installed for this
// tier but hasn't reported in yet. No Pi-hole row exists for the same
// reason: nothing in the backend reports its status at all yet. See
// sentinel/api/routes/system.py.
function buildRows(health, openAlerts) {
  const sec = health.security_services || {}
  const feeds = Object.values(health.threat_intel_feeds || {})
  // openAlerts is unfiltered by acknowledged/staleness (see DashboardPage.jsx)
  // — only resolved matters here. Already created_at-desc from the API, so
  // .find() below picks the most recent match per service.
  const unresolvedAlerts = openAlerts.filter((a) => !a.resolved)
  const feedsOk = feeds.length > 0 && feeds.every((f) => !f.error)
  const stalestFeedRefresh = feeds
    .map((f) => f.refreshed_at)
    .filter(Boolean)
    .sort()[0]

  const rows = [
    {
      key: 'postgres',
      icon: PostgresIcon,
      label: 'Postgres',
      ok: health.postgres?.reachable,
      detail: health.postgres?.reachable ? 'OK' : 'DOWN',
    },
    {
      key: 'redis',
      icon: RedisIcon,
      label: 'Redis',
      ok: health.redis?.reachable,
      detail: health.redis?.reachable ? 'OK' : 'DOWN',
    },
    {
      key: 'router_poll',
      icon: RouterIcon,
      label: 'XMO Adapter',
      ok: health.scheduler?.scheduler_running && !health.scheduler?.last_poll_error,
      detail: health.scheduler?.scheduler_running ? 'POLLING' : 'STOPPED',
    },
    {
      key: 'arp_watch',
      icon: RadarIcon,
      label: 'ARP Watch',
      ok: sec.arp_watch_active,
      detail: sec.arp_watch_active ? 'ACTIVE' : 'OFF',
    },
    {
      key: 'dhcp_watch',
      icon: TagIcon,
      label: 'DHCP Watch',
      ok: sec.dhcp_watch_active,
      detail: sec.dhcp_watch_active ? 'ACTIVE' : 'OFF',
    },
    {
      key: 'fingerprint',
      icon: FingerprintIcon,
      label: 'Passive Fingerprint',
      ok: sec.fingerprint_active,
      detail: sec.fingerprint_active ? 'ACTIVE' : 'OFF',
    },
    {
      key: 'nmap',
      icon: CrosshairIcon,
      label: 'Nmap Scanner',
      ok: !!sec.nmap_last_scan_at,
      detail: sec.nmap_last_scan_at ? <TimeAgo iso={sec.nmap_last_scan_at} /> : 'PENDING',
    },
    {
      key: 'opencanary',
      icon: CanaryIcon,
      label: 'OpenCanary',
      ok: !!sec.canary_last_check_at,
      detail: sec.canary_last_check_at ? <TimeAgo iso={sec.canary_last_check_at} /> : 'PENDING',
    },
    {
      key: 'threat_intel',
      icon: ShieldIcon,
      label: 'Threat Intel',
      ok: feedsOk,
      detail: stalestFeedRefresh ? <TimeAgo iso={stalestFeedRefresh} /> : 'PENDING',
    },
    {
      key: 'zeek_dns',
      icon: EyeIcon,
      label: 'Zeek DNS',
      ok: !!sec.zeek_dns_last_check_at,
      detail: sec.zeek_dns_last_check_at ? <TimeAgo iso={sec.zeek_dns_last_check_at} /> : 'PENDING',
    },
    {
      key: 'zeek_beacon',
      icon: PulseIcon,
      label: 'Zeek Beaconing',
      ok: !!sec.zeek_beacon_last_scan_at,
      detail: sec.zeek_beacon_last_scan_at ? <TimeAgo iso={sec.zeek_beacon_last_scan_at} /> : 'PENDING',
    },
    {
      key: 'clamav',
      icon: ShieldCheckIcon,
      label: 'ClamAV',
      ok: !!sec.clamav_reachable,
      detail: sec.clamav_reachable ? 'REACHABLE' : 'DOWN',
    },
    {
      key: 'suricata',
      icon: SirenIcon,
      label: 'Suricata IDS',
      ok: !!sec.suricata_last_check_at,
      detail: sec.suricata_last_check_at ? <TimeAgo iso={sec.suricata_last_check_at} /> : 'PENDING',
    },
    {
      key: 'wifi_monitor',
      icon: WifiIcon,
      label: 'WiFi Monitor',
      ok: sec.wifi_monitor_active,
      detail: sec.wifi_monitor_active ? 'ACTIVE' : 'OFF',
    },
  ]

  // ALERT overrides a row's normal display only while the service is
  // otherwise `ok` AND an unresolved alert of its mapped type(s) exists —
  // once the alert resolves, or the service itself goes off/unreachable,
  // the row falls back to its normal ok/detail above untouched.
  return rows.map((row) => {
    const types = ALERT_TYPES_BY_SERVICE[row.key]
    if (!row.ok || !types) return row
    const culprit = unresolvedAlerts.find((a) => types.has(a.alert_type))
    if (!culprit) return row
    return { ...row, alert: true, to: culprit.device_mac ? `/devices/${culprit.device_mac}` : '/alerts' }
  })
}

export function ServiceStatusPanel({ health, openAlerts = [] }) {
  // Separate query, separate cadence (see useServiceDetails) — a row's own
  // ok/detail must never wait on this, so it's looked up per-row below
  // rather than folded into buildRows/rows' memoization.
  const { data: details = {} } = useServiceDetails()
  // Older/degraded /api/health responses (scheduler not initialised) may
  // omit active_services entirely — fall back to showing everything rather
  // than an empty panel, since "unknown" shouldn't read as "nothing active".
  const activeServices = health?.security_services?.active_services
  // Memoized so this only recomputes when health/openAlerts actually change
  // (both poll on their own 15s cadence), not on every unrelated re-render
  // of an ancestor — see DesktopShell's Clock fix. Before a health value
  // exists, useMemo still runs (hooks can't be conditional) — health is
  // undefined the very first render, hence the null guard inside rather
  // than an early return above this hook.
  const rows = useMemo(() => {
    if (!health) return []
    return buildRows(health, openAlerts).filter((row) => !activeServices || activeServices.includes(row.key))
  }, [health, openAlerts, activeServices])

  if (!health) return <div className="text-[10px] text-text-muted">Loading…</div>

  return (
    <div className="flex h-full flex-col border border-border bg-surface p-4">
      <div className="mb-2 flex-shrink-0 text-[8px] tracking-[3px] text-text-muted">SERVICES</div>
      <div className="flex-1 overflow-y-auto">
        {rows.map((row) => (
          <Row
            key={row.key}
            icon={row.icon}
            label={row.label}
            ok={row.ok}
            detail={row.detail}
            alert={row.alert}
            to={row.to}
            info={details[row.key]}
          />
        ))}
      </div>
    </div>
  )
}
