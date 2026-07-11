const COLORS = {
  CRITICAL: 'bg-accent-red',
  WARNING: 'bg-accent-amber',
  INFO: 'bg-accent-blue',
}

export function SeverityBar({ severity }) {
  return <div className={`w-[2px] flex-shrink-0 self-stretch ${COLORS[severity] || COLORS.INFO}`} />
}
