export function PlaceholderPage({ title }) {
  return (
    <div className="p-6 text-text-secondary">
      <div className="mb-2 text-[10px] tracking-[2px] text-text-muted">{title.toUpperCase()}</div>
      <div className="text-sm">Coming in the next stage.</div>
    </div>
  )
}
