const TEXT = {
  green: 'text-accent-green',
  red: 'text-accent-red',
  amber: 'text-accent-amber',
  blue: 'text-accent-blue',
}
const BORDER = {
  green: 'border-accent-green',
  red: 'border-accent-red',
  amber: 'border-accent-amber',
  blue: 'border-accent-blue',
}

export function MetricCard({ label, value, sub, accent = 'green', tag }) {
  return (
    <div className="relative overflow-hidden border border-border bg-surface p-4">
      <div className={`absolute right-0 top-0 h-5 w-5 border-r-2 border-t-2 ${BORDER[accent]}`} />
      <div className="mb-2 flex justify-between text-[8px] tracking-[3px] text-text-muted">
        <span>{label}</span>
        {tag && <em className={`not-italic ${TEXT[accent]}`}>{tag}</em>}
      </div>
      <div className={`font-heading text-[44px] font-bold leading-none tracking-tight ${TEXT[accent]}`}>
        {value}
      </div>
      {sub && <div className="mt-1 text-[8px] tracking-wide text-text-secondary">{sub}</div>}
    </div>
  )
}
