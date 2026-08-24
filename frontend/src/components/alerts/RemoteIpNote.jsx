function formatBytes(bytes) {
  if (bytes == null) return '—'
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

/** Remote-IP correlation from SentinelScheduler._spike_ip_enrichment_job
 * (Alert.raw_data.remote_ip — see sentinel/security/zeek_parser.py's
 * ZeekConnVolumeCorrelator). Only relevant on ANOMALOUS_VOLUME/HIGH_UPLOAD/
 * WAN_BANDWIDTH_SPIKE alerts — every other alert type never carries
 * ip_enrichment_done at all, so this renders nothing for them, same as before.
 *
 * Four distinct states. Three were previously collapsed into one ("nothing
 * shown"), which is exactly what prompted the ip_enrichment_done branch
 * below: an admin looking at a HIGH_UPLOAD alert with no remote IP shown
 * had no way to tell "hasn't been checked yet" apart from "checked, found
 * nothing to attribute it to" — the second is a real, common, non-broken
 * outcome (e.g. LAN-to-LAN traffic, or no matching Zeek flow in the
 * correlation window) but looked identical to a gap.
 *
 * The fourth state (green) is the destination-found-but-internal case —
 * another device on this LAN, not a possible external threat, so it reads
 * as informational rather than the blue "worth a look" REMOTE IP treatment
 * or the red MALICIOUS DESTINATION one. remote_ip_internal is never even
 * computed unless a destination was actually found (see
 * SentinelScheduler._enrich_spike_alert), so this only ever applies
 * alongside a real ip. */
export function RemoteIpNote({ rawData }) {
  const ip = rawData?.remote_ip
  if (ip && rawData.remote_ip_internal) {
    return (
      <div className="mt-1 border-l-2 border-accent-green/40 py-0.5 pl-2 text-[9px] leading-snug text-accent-green">
        <span className="mr-1 tracking-wider">INTERNAL DESTINATION:</span>
        {ip} — another device on this network, not checked against threat intel
        ({formatBytes(rawData.remote_ip_bytes)}, {rawData.remote_ip_connections ?? 0} conn.)
      </div>
    )
  }
  if (ip) {
    const malicious = rawData.remote_ip_malicious
    return (
      <div
        className={`mt-1 border-l-2 py-0.5 pl-2 text-[9px] leading-snug ${
          malicious ? 'border-accent-red/40 text-accent-red' : 'border-accent-blue/40 text-text-secondary'
        }`}
      >
        <span className={`mr-1 tracking-wider ${malicious ? 'text-accent-red' : 'text-accent-blue'}`}>
          {malicious ? 'MALICIOUS DESTINATION:' : 'REMOTE IP:'}
        </span>
        {ip} ({formatBytes(rawData.remote_ip_bytes)}, {rawData.remote_ip_connections ?? 0} conn.)
      </div>
    )
  }

  if (rawData?.ip_enrichment_done) {
    return (
      <div className="mt-1 border-l-2 border-border py-0.5 pl-2 text-[9px] leading-snug text-text-muted">
        No destination correlated (checked against Zeek's connection log — either LAN-only
        traffic, or no matching flow in the alert's time window).
      </div>
    )
  }

  return null
}
