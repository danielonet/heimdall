import { StatusDot } from '../StatusDot'
import { TimeAgo } from '../TimeAgo'
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
} from './ServiceIcons'

function Row({ icon: Icon, label, ok, detail }) {
  return (
    <div className="flex items-center justify-between border-b border-border/50 py-1.5 text-[10px] last:border-none">
      <span className={`flex items-center gap-1.5 ${ok ? 'text-text-secondary' : 'text-text-muted'}`}>
        <Icon className={`h-3 w-3 flex-shrink-0 ${ok ? 'text-accent-green' : 'text-text-muted'}`} />
        {label}
      </span>
      <span className={`flex items-center gap-1.5 ${ok ? 'text-accent-green' : 'text-text-muted'}`}>
        <StatusDot variant={ok ? 'green' : 'muted'} pulse={ok} />
        {detail}
      </span>
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
function buildRows(health) {
  const sec = health.security_services || {}
  const feeds = Object.values(health.threat_intel_feeds || {})
  const feedsOk = feeds.length > 0 && feeds.every((f) => !f.error)
  const stalestFeedRefresh = feeds
    .map((f) => f.refreshed_at)
    .filter(Boolean)
    .sort()[0]

  return [
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
  ]
}

export function ServiceStatusPanel({ health }) {
  if (!health) return <div className="text-[10px] text-text-muted">Loading…</div>

  // Older/degraded /api/health responses (scheduler not initialised) may
  // omit active_services entirely — fall back to showing everything rather
  // than an empty panel, since "unknown" shouldn't read as "nothing active".
  const activeServices = health.security_services?.active_services
  const rows = buildRows(health).filter((row) => !activeServices || activeServices.includes(row.key))

  return (
    <div className="flex h-full flex-col border border-border bg-surface p-4">
      <div className="mb-2 flex-shrink-0 text-[8px] tracking-[3px] text-text-muted">SERVICES</div>
      <div className="flex-1 overflow-y-auto">
        {rows.map((row) => (
          <Row key={row.key} icon={row.icon} label={row.label} ok={row.ok} detail={row.detail} />
        ))}
      </div>
    </div>
  )
}
