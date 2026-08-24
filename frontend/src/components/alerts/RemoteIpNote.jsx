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
 * Three distinct states, previously collapsed into one ("nothing shown"),
 * which is exactly what prompted this: an admin looking at a HIGH_UPLOAD
 * alert with no remote IP shown had no way to tell "hasn't been checked
 * yet" apart from "checked, found nothing to attribute it to" — the second
 * one is a real, common, non-broken outcome (e.g. the traffic was LAN-to-
 * LAN, or Zeek's conn.log had no matching flow in the correlation window)
 * but looked identical to a gap. ip_enrichment_done (set unconditionally
 * once _enrich_spike_alert has run, whether or not it found a talker) is
 * what actually distinguishes the two — not just remote_ip's presence. */
export function RemoteIpNote({ rawData }) {
  const ip = rawData?.remote_ip
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
