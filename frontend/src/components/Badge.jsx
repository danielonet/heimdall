const VARIANTS = {
  success: 'text-accent-green border-accent-green/30 bg-accent-green/5',
  warning: 'text-accent-amber border-accent-amber/30 bg-accent-amber/5',
  danger: 'text-accent-red border-accent-red/30 bg-accent-red/5',
  info: 'text-accent-blue border-accent-blue/30 bg-accent-blue/5',
  port: 'text-accent-amber border-accent-amber/30 bg-accent-amber/5',
  // Deliberately not danger/warning-colored — an alert this old is still
  // open, but shouldn't read as urgent every time the Alerts page loads.
  // See AppSettings.alert_stale_hours.
  muted: 'text-text-muted border-border bg-surface',
}

export function Badge({ variant = 'info', title, children }) {
  return (
    <span
      title={title}
      className={`inline-block whitespace-nowrap border px-1.5 py-0.5 text-[9px] tracking-wider ${VARIANTS[variant]}`}
    >
      {children}
    </span>
  )
}
