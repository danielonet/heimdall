import { useEffect, useState } from 'react'
import { useSettings, useUpdateSettings } from '../../hooks/useSettings'

const ROUTER_LABELS = {
  sagemcom: 'Sagemcom F@st 5670',
  miwifi: 'Redmi router (MiWiFi)',
}

// Which configured router is "active" — feeds the detection pipeline, WAN
// bandwidth tracking, auto-block, and the ROUTER panel above this one on
// the Equipment page. Only ever offers routers useSettings().available_routers
// actually lists (i.e. never 'miwifi' before it has credentials) — see
// sentinel/api/routes/settings.py's `available_routers`.
export function PrimaryRouterSelect() {
  const { data, isLoading } = useSettings()
  const mutation = useUpdateSettings()
  const [selected, setSelected] = useState('sagemcom')

  useEffect(() => {
    if (data) setSelected(data.active_router)
  }, [data])

  const isDirty = data && selected !== data.active_router
  const options = data?.available_routers || ['sagemcom']

  return (
    <div className="mt-2 border-t border-border/50 pt-2">
      <div className="mb-1.5 text-[8px] tracking-[3px] text-text-muted">PRIMARY ROUTER</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        Which router Heimdall treats as the base network endpoint — threat detection, WAN status, and
        auto-block all run against this one. The other configured router (if any) is still monitored for
        device/traffic visibility.
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && (
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label htmlFor="active-router" className="mb-1 block text-[9px] tracking-wider text-text-muted">
              ROUTER
            </label>
            <select
              id="active-router"
              value={selected}
              onChange={(e) => setSelected(e.target.value)}
              className="w-56 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
            >
              {options.map((router) => (
                <option key={router} value={router}>
                  {ROUTER_LABELS[router] || router}
                </option>
              ))}
            </select>
          </div>
          <button
            type="button"
            disabled={!isDirty || mutation.isPending}
            onClick={() => mutation.mutate({ active_router: selected })}
            className="border border-accent-green/30 bg-accent-green/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
          >
            {mutation.isPending ? 'SAVING…' : 'SAVE'}
          </button>
        </div>
      )}

      {options.length < 2 && (
        <p className="mt-1.5 text-[9px] text-text-muted">Add the Redmi router in the Routers list above to enable switching.</p>
      )}
      {mutation.isError && <div className="mt-2 text-[9px] text-accent-red">{mutation.error.message}</div>}
    </div>
  )
}
