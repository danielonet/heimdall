function formatBytes(bytes) {
  if (bytes == null) return '—'
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}

/** Remote-IP correlation from SentinelScheduler._spike_ip_enrichment_job
 * (Alert.raw_data.remote_ip — see sentinel/security/zeek_parser.py's
 * ZeekConnVolumeCorrelator). Only present on ANOMALOUS_VOLUME/HIGH_UPLOAD/
 * WAN_BANDWIDTH_SPIKE alerts, and only once Zeek's conn.log correlation has
 * actually resolved a top talker — renders nothing otherwise, so every
 * other alert type and every un-enriched spike alert are unaffected.
 */
export function RemoteIpNote({ rawData }) {
  const ip = rawData?.remote_ip
  if (!ip) return null

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
