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

// Only real, wired signals — no Pi-hole row, since nothing in the backend
// reports its status. See sentinel/api/routes/system.py.
export function ServiceStatusPanel({ health }) {
  if (!health) return <div className="text-[10px] text-text-muted">Loading…</div>

  const sec = health.security_services || {}
  const feeds = Object.values(health.threat_intel_feeds || {})
  const feedsOk = feeds.length > 0 && feeds.every((f) => !f.error)
  const stalestFeedRefresh = feeds
    .map((f) => f.refreshed_at)
    .filter(Boolean)
    .sort()[0]

  return (
    <div className="flex h-full flex-col border border-border bg-surface p-4">
      <div className="mb-2 flex-shrink-0 text-[8px] tracking-[3px] text-text-muted">SERVICES</div>
      <div className="flex-1 overflow-y-auto">
        <Row
          icon={PostgresIcon}
          label="Postgres"
          ok={health.postgres?.reachable}
          detail={health.postgres?.reachable ? 'OK' : 'DOWN'}
        />
        <Row
          icon={RedisIcon}
          label="Redis"
          ok={health.redis?.reachable}
          detail={health.redis?.reachable ? 'OK' : 'DOWN'}
        />
        <Row
          icon={RouterIcon}
          label="XMO Adapter"
          ok={health.scheduler?.scheduler_running && !health.scheduler?.last_poll_error}
          detail={health.scheduler?.scheduler_running ? 'POLLING' : 'STOPPED'}
        />
        <Row
          icon={RadarIcon}
          label="ARP Watch"
          ok={sec.arp_watch_active}
          detail={sec.arp_watch_active ? 'ACTIVE' : 'OFF'}
        />
        <Row
          icon={TagIcon}
          label="DHCP Watch"
          ok={sec.dhcp_watch_active}
          detail={sec.dhcp_watch_active ? 'ACTIVE' : 'OFF'}
        />
        <Row
          icon={FingerprintIcon}
          label="Passive Fingerprint"
          ok={sec.fingerprint_active}
          detail={sec.fingerprint_active ? 'ACTIVE' : 'OFF'}
        />
        <Row
          icon={CrosshairIcon}
          label="Nmap Scanner"
          ok={!!sec.nmap_last_scan_at}
          detail={sec.nmap_last_scan_at ? <TimeAgo iso={sec.nmap_last_scan_at} /> : 'PENDING'}
        />
        <Row
          icon={CanaryIcon}
          label="OpenCanary"
          ok={!!sec.canary_last_check_at}
          detail={sec.canary_last_check_at ? <TimeAgo iso={sec.canary_last_check_at} /> : 'PENDING'}
        />
        <Row
          icon={ShieldIcon}
          label="Threat Intel"
          ok={feedsOk}
          detail={stalestFeedRefresh ? <TimeAgo iso={stalestFeedRefresh} /> : 'PENDING'}
        />
        <Row
          icon={EyeIcon}
          label="Zeek DNS"
          ok={!!sec.zeek_dns_last_check_at}
          detail={sec.zeek_dns_last_check_at ? <TimeAgo iso={sec.zeek_dns_last_check_at} /> : 'PENDING'}
        />
        <Row
          icon={PulseIcon}
          label="Zeek Beaconing"
          ok={!!sec.zeek_beacon_last_scan_at}
          detail={sec.zeek_beacon_last_scan_at ? <TimeAgo iso={sec.zeek_beacon_last_scan_at} /> : 'PENDING'}
        />
        <Row
          icon={ShieldCheckIcon}
          label="ClamAV"
          ok={!!sec.clamav_reachable}
          detail={sec.clamav_reachable ? 'REACHABLE' : 'DOWN'}
        />
        <Row
          icon={SirenIcon}
          label="Suricata IDS"
          ok={!!sec.suricata_last_check_at}
          detail={sec.suricata_last_check_at ? <TimeAgo iso={sec.suricata_last_check_at} /> : 'PENDING'}
        />
      </div>
    </div>
  )
}
