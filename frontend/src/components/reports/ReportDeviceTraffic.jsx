import { formatBytes } from '../../lib/format'

/** device_label already comes pre-resolved from the backend (nickname >
 * hostname > MAC — resolve_device_label in sentinel/notifications/
 * digest.py, mirroring this app's own deviceDisplayName precedence), so
 * this just lays it out — same PER_DEVICE-only restriction as the email's
 * own traffic section (CLAUDE.md rule 5: a wired device sharing its port
 * has no real per-device figure, so it's excluded rather than misattributed). */
export function ReportDeviceTraffic({ traffic }) {
  if (!traffic || traffic.length === 0) {
    return <div className="p-4 text-center text-[10px] text-text-muted">No per-device traffic in this window.</div>
  }

  return (
    <div>
      <table className="w-full text-left text-[10px]">
        <thead>
          <tr className="text-[9px] tracking-wider text-text-muted">
            <th className="px-3 py-2 font-normal">DEVICE</th>
            <th className="px-3 py-2 text-right font-normal">UPLOAD</th>
            <th className="px-3 py-2 text-right font-normal">DOWNLOAD</th>
          </tr>
        </thead>
        <tbody>
          {traffic.map((t) => (
            <tr key={t.device_label} className="border-t border-border/50">
              <td className="px-3 py-2 text-text-primary">{t.device_label}</td>
              <td className="px-3 py-2 text-right text-text-secondary">{formatBytes(t.upload_bytes)}</td>
              <td className="px-3 py-2 text-right text-text-secondary">{formatBytes(t.download_bytes)}</td>
            </tr>
          ))}
        </tbody>
      </table>
      <div className="border-t border-border/50 p-2 text-[9px] leading-relaxed text-text-muted">
        Wired devices sharing a physical port aren't broken out individually — only a combined port total is
        measurable for them.
      </div>
    </div>
  )
}
