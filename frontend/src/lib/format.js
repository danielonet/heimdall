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

// A rate stored as kilobits per second (bits / 1024), e.g. a switch port's throughput_*_kbps.
export function formatBitRate(kbps) {
  if (kbps == null) return '—'
  if (kbps >= 1024) return `${(kbps / 1024).toFixed(1)} Mb/s`
  return `${Math.round(kbps)} kb/s`
}
