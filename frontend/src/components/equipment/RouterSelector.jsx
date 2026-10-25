import { useEffect, useRef, useState } from 'react'
import { Badge } from '../Badge'
import { RouterLoginModal } from './RouterLoginModal'
import { useRemoveRouter, useRouterCatalog, useSelectedRouters } from '../../hooks/useRouters'

// Pick one or more router families from the catalog (multi-select dropdown);
// every picked router gets a row with a LOGIN button that opens the
// username/password popup. A router counts as saved once its login has been
// stored — a freshly ticked one stays "pending" (and opens the popup) until then.
export function RouterSelector() {
  const { data: catalog = [], isLoading } = useRouterCatalog()
  const { data: selected = [] } = useSelectedRouters()
  const removeMutation = useRemoveRouter()
  const [pending, setPending] = useState([])
  const [open, setOpen] = useState(false)
  const [editing, setEditing] = useState(null)
  const menuRef = useRef(null)

  useEffect(() => {
    function handleClick(e) {
      if (menuRef.current && !menuRef.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  const savedIds = selected.map((s) => s.router_id)
  const pickedIds = catalog.filter((s) => savedIds.includes(s.id) || pending.includes(s.id)).map((s) => s.id)
  const byId = Object.fromEntries(selected.map((s) => [s.router_id, s]))

  function toggle(spec) {
    if (pickedIds.includes(spec.id)) {
      // The Sagemcom is the permanent household router — it can't be deselected.
      if (spec.id === 'sagemcom-xmo') return
      if (savedIds.includes(spec.id)) {
        if (!window.confirm(`Remove ${spec.label} and forget its saved password?`)) return
        removeMutation.mutate({ spec })
      }
      setPending((p) => p.filter((id) => id !== spec.id))
    } else {
      setPending((p) => [...p, spec.id])
      setEditing(spec)
    }
  }

  function closeModal() {
    setEditing(null)
    // Anything that didn't get saved is dropped from the pending list.
    setPending((p) => p.filter((id) => savedIds.includes(id)))
  }

  return (
    <div className="mt-2 border-t border-border/50 pt-2">
      <div className="mb-1.5 text-[8px] tracking-[3px] text-text-muted">ROUTERS</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        Choose the router(s) on your network and add a login for each. Logins are kept in secret files on the
        Heimdall host.
      </p>

      <div className="relative inline-block" ref={menuRef}>
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          disabled={isLoading}
          aria-haspopup="listbox"
          aria-expanded={open}
          className="w-64 border border-border bg-bg px-3 py-1.5 text-left text-[11px] text-text-primary outline-none hover:border-border-active"
        >
          {pickedIds.length ? `${pickedIds.length} router${pickedIds.length > 1 ? 's' : ''} selected` : 'Select routers…'}
          <span className="float-right text-text-muted">▾</span>
        </button>
        {open && (
          <ul
            role="listbox"
            aria-multiselectable="true"
            className="absolute z-20 mt-1 max-h-72 w-72 overflow-y-auto border border-border-active bg-surface-elevated"
          >
            {catalog.map((spec) => (
              <li key={spec.id} role="option" aria-selected={pickedIds.includes(spec.id)}>
                <label className="flex cursor-pointer items-center gap-2 px-3 py-1.5 text-[11px] text-text-primary hover:bg-surface">
                  <input
                    type="checkbox"
                    checked={pickedIds.includes(spec.id)}
                    disabled={spec.id === 'sagemcom-xmo'}
                    onChange={() => toggle(spec)}
                  />
                  <span className="flex-1">{spec.label}</span>
                  {!spec.implemented && <span className="text-[8px] tracking-wider text-text-muted">PLANNED</span>}
                </label>
              </li>
            ))}
          </ul>
        )}
      </div>

      <ul className="mt-3 space-y-1.5">
        {catalog
          .filter((spec) => pickedIds.includes(spec.id))
          .map((spec) => {
            const entry = byId[spec.id]
            return (
              <li key={spec.id} className="flex flex-wrap items-center gap-2 border border-border/60 px-3 py-1.5">
                <div className="min-w-48 flex-1">
                  <div className="text-[11px] text-text-primary">{spec.label}</div>
                  <div className="text-[9px] text-text-muted">
                    {spec.protocol}
                    {entry?.host ? ` · ${entry.host}` : ''}
                    {entry?.username ? ` · ${entry.username}` : ''}
                  </div>
                </div>
                <Badge variant={spec.implemented ? 'success' : 'muted'} title={spec.implemented ? undefined : 'Login can be saved; the adapter is not built yet'}>
                  {spec.implemented ? 'SUPPORTED' : 'PLANNED'}
                </Badge>
                <Badge variant={entry?.password_configured ? 'info' : 'warning'}>
                  {entry?.password_configured ? 'LOGIN SAVED' : 'NO LOGIN'}
                </Badge>
                <button
                  type="button"
                  onClick={() => setEditing(spec)}
                  className="border border-accent-green/30 bg-accent-green/5 px-3 py-1 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20"
                >
                  LOGIN
                </button>
              </li>
            )
          })}
      </ul>
      {removeMutation.isError && <div className="mt-2 text-[9px] text-accent-red">{removeMutation.error.message}</div>}

      {editing && <RouterLoginModal spec={editing} current={byId[editing.id]} onClose={closeModal} />}
    </div>
  )
}
