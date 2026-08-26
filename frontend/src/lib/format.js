// Shared byte-count formatter — was duplicated identically in PortCard.jsx
// and RemoteIpNote.jsx (both cap at MB, since traffic deltas rarely exceed
// that). Pulled out here, with a GB tier added, for ServiceHoverCard's
// Postgres database size / Redis memory usage figures, which routinely do.
export function formatBytes(bytes) {
  if (bytes == null) return '—'
  if (bytes >= 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`
  if (bytes >= 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${bytes} B`
}
