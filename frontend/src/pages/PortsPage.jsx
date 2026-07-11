import { usePorts } from '../hooks/usePorts'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { PortCard } from '../components/ports/PortCard'

export function PortsPage() {
  const { data: ports, isLoading } = usePorts()
  const mode = useLayoutMode()

  // Viewport-based Tailwind breakpoints (sm:/lg:/xl:) would be wrong here:
  // ?mobile=1 can force the narrow mobile shell on a wide desktop viewport,
  // and vice versa, so the grid must key off the actual layout mode rather
  // than window width.
  const gridClass = mode === 'mobile' ? 'grid grid-cols-1 gap-3' : 'grid grid-cols-3 gap-4 xl:grid-cols-5'

  return (
    <div className="p-4">
      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}
      {!isLoading && (!ports || ports.length === 0) && (
        <div className="text-[10px] text-text-muted">No port data yet.</div>
      )}
      <div className={gridClass}>
        {(ports || []).map((p) => (
          <PortCard key={p.port_alias} port={p} />
        ))}
      </div>
    </div>
  )
}
