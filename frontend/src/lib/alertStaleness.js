/** Shared staleness math for AppSettings.alert_stale_hours (see
 * sentinel/db/models.py and GET/PATCH /api/settings).
 *
 * Two distinct uses of the same threshold:
 *  - staleBeforeIso(): an ISO cutoff to pass as the `from` query param on
 *    useAlerts/useAlertGroups, so the Dashboard and Network Map's queries
 *    never even receive alerts older than the threshold — same `from`
 *    filter the Alerts page's own 24h/7d range buttons already use (see
 *    AlertsPage.jsx's rangeStartIso), just driven by the configured
 *    threshold instead of a user-picked range.
 *  - isStale(): a plain boolean for the Alerts page itself, which does NOT
 *    filter — it fetches full history and marks old rows STALE instead of
 *    hiding them.
 */

/** ISO timestamp `hours` before now, or null if hours is unset/loading —
 * callers should skip adding a `from` param at all when this is null,
 * rather than filtering out everything. */
export function staleBeforeIso(hours) {
  if (!hours) return null
  return new Date(Date.now() - hours * 3600_000).toISOString()
}

/** Whether an ISO timestamp is older than `hours` ago. False (never stale)
 * if either input is missing — an alert with no timestamp, or a threshold
 * that hasn't loaded yet, shouldn't flash as STALE. */
export function isStale(isoTimestamp, hours) {
  if (!isoTimestamp || !hours) return false
  return Date.now() - new Date(isoTimestamp).getTime() > hours * 3600_000
}
