import { useEffect, useState } from 'react'
import { useSettings, useUpdateSettings } from '../../hooks/useSettings'
import { useMonitorInterfaces } from '../../hooks/useWifi'

function ChipList({ label, placeholder, values, onChange, validate }) {
  const [draft, setDraft] = useState('')

  function add() {
    const value = draft.trim()
    if (!value || values.includes(value)) return
    if (validate && !validate(value)) return
    onChange([...values, value])
    setDraft('')
  }

  return (
    <div>
      <label className="mb-1 block text-[9px] tracking-wider text-text-muted">{label}</label>
      <div className="mb-1.5 flex flex-wrap gap-1.5">
        {values.map((v) => (
          <span
            key={v}
            className="flex items-center gap-1 border border-border bg-bg px-2 py-0.5 text-[10px] text-text-secondary"
          >
            {v}
            <button
              type="button"
              onClick={() => onChange(values.filter((x) => x !== v))}
              className="text-text-muted hover:text-accent-red"
            >
              ×
            </button>
          </span>
        ))}
        {values.length === 0 && <span className="text-[9px] text-text-muted">None configured</span>}
      </div>
      <div className="flex gap-1.5">
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') {
              e.preventDefault()
              add()
            }
          }}
          placeholder={placeholder}
          className="flex-1 border border-border bg-bg px-2 py-1 text-[10px] text-text-primary outline-none focus:border-border-active"
        />
        <button
          type="button"
          onClick={add}
          className="border border-border px-2 py-1 text-[10px] text-text-secondary hover:border-border-active"
        >
          ADD
        </button>
      </div>
    </div>
  )
}

// The "WIFI MONITOR" settings panel — configures the passive 802.11
// monitor-mode watcher (rogue-AP detection + nearby-device sightings, see
// sentinel/security/wifi_monitor.py and the WIFI nav tab). Mirrors
// NetworkInterfaceSection's dirty-tracking pattern, extended with two
// chip-list editors since this feature needs more than one field to be
// useful at all — an interface alone can't alert on anything without at
// least one protected SSID.
export function WifiMonitorSection() {
  const { data, isLoading } = useSettings()
  const { data: interfaces, isLoading: interfacesLoading } = useMonitorInterfaces()
  const mutation = useUpdateSettings()

  const [iface, setIface] = useState('')
  const [ssids, setSsids] = useState([])
  const [bssids, setBssids] = useState([])

  useEffect(() => {
    if (data) {
      setIface(data.wifi_monitor_iface || '')
      setSsids(data.wifi_protected_ssids || [])
      setBssids(data.wifi_trusted_bssids || [])
    }
  }, [data])

  const isDirty =
    data &&
    (iface !== (data.wifi_monitor_iface || '') ||
      JSON.stringify(ssids) !== JSON.stringify(data.wifi_protected_ssids || []) ||
      JSON.stringify(bssids) !== JSON.stringify(data.wifi_trusted_bssids || []))

  const macRe = /^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/

  return (
    <div>
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">WIFI MONITOR</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        Passive 802.11 monitoring for rogue/evil-twin access points and nearby unassociated devices —
        needs a dedicated WiFi adapter that supports monitor mode (can't be the same NIC serving your
        LAN connection). See the WIFI tab.
      </p>

      {(isLoading || interfacesLoading) && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && !interfacesLoading && (
        <div className="space-y-3">
          <div>
            <label htmlFor="wifi-monitor-iface" className="mb-1 block text-[9px] tracking-wider text-text-muted">
              ADAPTER
            </label>
            {interfaces && interfaces.length > 0 ? (
              <select
                id="wifi-monitor-iface"
                value={iface}
                onChange={(e) => setIface(e.target.value)}
                className="w-56 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
              >
                <option value="">Disabled</option>
                {iface && !interfaces.includes(iface) && (
                  <option value={iface}>{iface} (not currently detected)</option>
                )}
                {interfaces.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
            ) : (
              <div className="text-[10px] text-accent-amber">
                No monitor-capable WiFi adapter detected on this host.
              </div>
            )}
          </div>

          <ChipList
            label="PROTECTED SSIDS"
            placeholder="e.g. MyHomeWiFi"
            values={ssids}
            onChange={setSsids}
          />
          <ChipList
            label="TRUSTED BSSIDS (your own APs' real MACs)"
            placeholder="aa:bb:cc:dd:ee:ff"
            values={bssids}
            onChange={setBssids}
            validate={(v) => macRe.test(v)}
          />

          <button
            type="button"
            disabled={!isDirty || mutation.isPending}
            onClick={() =>
              mutation.mutate({
                wifi_monitor_iface: iface || null,
                wifi_protected_ssids: ssids,
                wifi_trusted_bssids: bssids,
              })
            }
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
