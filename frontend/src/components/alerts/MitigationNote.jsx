/** Canned "what to do about this" guidance from the backend
 * (Alert.mitigation — see sentinel/security/remediation.py). Only
 * confirmed-attack alert types carry one; renders nothing otherwise, so
 * ML/detector-pipeline alerts (vendor-mismatch, anomalous-volume, etc.)
 * are unaffected.
 */
export function MitigationNote({ text }) {
  if (!text) return null
  return (
    <div className="mt-1 border-l-2 border-accent-amber/40 py-0.5 pl-2 text-[9px] leading-snug text-text-secondary">
      <span className="mr-1 tracking-wider text-accent-amber">MITIGATION:</span>
      {text}
    </div>
  )
}
