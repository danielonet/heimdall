import { formatBytes } from '../../lib/format'

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
 * A second ambiguity, fixed the same way: an external-but-clean IP (found,
 * checked against threat intel, no match) used to render as a neutral blue
 * "REMOTE IP: x.x.x.x" — factually correct, but read as "here's where it
 * went" rather than "we checked this and it's fine," which is exactly what
 * a clean verdict means. remote_ip_malicious is always present (true or
 * false) whenever remote_ip is and it's not internal — SentinelScheduler.
 * _enrich_spike_alert sets both together — so `malicious === false` here
 * is a real, positive "checked, no match" result, not just "we don't know
 * yet." Now shares the same green/"nothing to worry about" treatment as
 * the internal case, with its own label so the two stay distinguishable,
 * plus an explicit note that no block action was taken (only a malicious
 * verdict ever triggers one — see the red branch, which escalates via a
 * separate MALICIOUS_TRAFFIC_DESTINATION alert rather than blocking from
 * here directly). */
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
  if (ip && rawData.remote_ip_malicious === false) {
    return (
      <div className="mt-1 border-l-2 border-accent-green/40 py-0.5 pl-2 text-[9px] leading-snug text-accent-green">
        <span className="mr-1 tracking-wider">VERIFIED CLEAN:</span>
        {ip} ({formatBytes(rawData.remote_ip_bytes)}, {rawData.remote_ip_connections ?? 0} conn.)
        <div className="mt-0.5 text-text-muted">
          Checked against the threat-intel IP database — no match. No block action was taken.
        </div>
      </div>
    )
  }
  if (ip) {
    return (
      <div className="mt-1 border-l-2 border-accent-red/40 py-0.5 pl-2 text-[9px] leading-snug text-accent-red">
        <span className="mr-1 tracking-wider">MALICIOUS DESTINATION:</span>
        {ip} ({formatBytes(rawData.remote_ip_bytes)}, {rawData.remote_ip_connections ?? 0} conn.)
        <div className="mt-0.5 text-text-muted">
          Flagged by threat intelligence — a separate MALICIOUS_TRAFFIC_DESTINATION alert was
          raised for this device (auto-blocked if that setting is armed).
        </div>
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
