import { useEffect, useState } from 'react'
import { useNetworkInterfaces, useSettings, useUpdateSettings } from '../../hooks/useSettings'

export function NetworkInterfaceSection() {
  const { data, isLoading } = useSettings()
  const { data: interfaces, isLoading: interfacesLoading } = useNetworkInterfaces()
  const mutation = useUpdateSettings()
  const [selected, setSelected] = useState('')

  // Only seed the dropdown from the server once it's actually loaded — an
  // effect (not a lazy useState initializer) because the fetch resolves
  // after first render.
  useEffect(() => {
    if (data) setSelected(data.sniff_iface)
  }, [data])

  const isDirty = data && selected !== data.sniff_iface

  return (
    <div className="border border-border bg-surface p-3">
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">NETWORK INTERFACE</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        The LAN-facing NIC ARP watch and passive fingerprinting listen on. Applies immediately.
      </p>

      {(isLoading || interfacesLoading) && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && !interfacesLoading && (
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <label htmlFor="sniff-iface" className="mb-1 block text-[9px] tracking-wider text-text-muted">
              INTERFACE
            </label>
            {interfaces && interfaces.length > 0 ? (
              <select
                id="sniff-iface"
                value={selected}
                onChange={(e) => setSelected(e.target.value)}
                className="w-48 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
              >
                {/* The currently configured interface may have disappeared
                    (unplugged dongle, renamed NIC) — keep it selectable so
                    the dropdown doesn't silently jump to something else. */}
                {selected && !interfaces.includes(selected) && (
                  <option value={selected}>{selected} (not currently detected)</option>
                )}
                {interfaces.map((iface) => (
                  <option key={iface} value={iface}>
                    {iface}
                  </option>
                ))}
              </select>
            ) : (
              <div className="text-[10px] text-accent-amber">No network interfaces detected.</div>
            )}
          </div>
          <button
            type="button"
            disabled={!isDirty || mutation.isPending}
            onClick={() => mutation.mutate({ sniff_iface: selected })}
            className="border border-accent-green/30 bg-accent-green/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
          >
            {mutation.isPending ? 'SAVING…' : 'SAVE'}
          </button>
        </div>
      )}

      {mutation.isError && <div className="mt-2 text-[9px] text-accent-red">{mutation.error.message}</div>}
    </div>
  )
}
