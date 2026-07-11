const WEIGHTS = { CRITICAL: 20, WARNING: 8, INFO: 2 }

/** Simple client-side derived score (weighted count of unresolved alerts) —
 * there is no backend "threat score" field, so this isn't invented data from
 * the API, just a display-only summary of alerts already fetched. */
export function computeThreatScore(alerts) {
  if (!alerts?.length) return 0
  const score = alerts.reduce((sum, a) => sum + (a.resolved ? 0 : (WEIGHTS[a.severity] ?? 0)), 0)
  return Math.min(100, score)
}
