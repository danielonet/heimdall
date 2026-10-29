import { useEffect, useState } from 'react'
import { useSettings, useUpdateSettings } from '../../hooks/useSettings'
import { useMonitorInterfaces, useWifiSuggestions } from '../../hooks/useWifi'

function ChipList({ label, hint, placeholder, values, onChange, validate }) {
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
      {hint && <p className="mb-1.5 text-[9px] leading-relaxed text-text-muted">{hint}</p>}
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

// "Detect from my router": fills the two lists below without typing. The SSIDs come from the router itself; the
// access points are the ones the monitor adapter has heard broadcasting those names. An attacker's copy would be
// heard too, so only the ones whose manufacturer prefix matches the router are ticked, and nothing is saved until
// the admin presses SAVE.
function DetectPanel({ onApply }) {
  const mutation = useWifiSuggestions()
  const [picked, setPicked] = useState({})
  const data = mutation.data

  function detect() {
    mutation.mutate(undefined, {
      onSuccess: (d) => setPicked(Object.fromEntries(d.candidates.map((c) => [c.bssid, c.matches_router]))),
    })
  }

  return (
    <div className="border border-border bg-bg p-2.5">
      <p className="mb-2 text-[9px] leading-relaxed text-text-muted">
        Don't know these values? Heimdall can ask your router for its WiFi names and listen for the access points
        broadcasting them. Needs the adapter above to be set and saved.
      </p>
      <button
        type="button"
        onClick={detect}
        disabled={mutation.isPending}
        className="border border-border px-2 py-1 text-[10px] tracking-wider text-text-secondary hover:border-border-active disabled:opacity-40"
      >
        {mutation.isPending ? 'ASKING THE ROUTER…' : 'DETECT FROM MY ROUTER'}
      </button>
      {mutation.isError && <div className="mt-2 text-[9px] text-accent-red">{mutation.error.message}</div>}
      {data && (
        <div className="mt-2 space-y-1.5">
          <div className="text-[10px] text-text-secondary">
            {data.protected_ssids.length === 0
              ? 'The router reported no WiFi names.'
              : `Your router broadcasts: ${data.protected_ssids.join(', ')}`}
          </div>
          {data.candidates.map((c) => (
            <label key={c.bssid} className="flex items-center gap-2 text-[10px] text-text-secondary">
              <input
                type="checkbox"
                checked={Boolean(picked[c.bssid])}
                onChange={(e) => setPicked((p) => ({ ...p, [c.bssid]: e.target.checked }))}
              />
              <span className="font-mono">{c.bssid}</span>
              <span>
                {c.ssid} · ch {c.channel ?? '?'} · {c.signal_dbm ?? '?'} dBm
              </span>
              <span className={c.matches_router ? 'text-accent-green' : 'text-accent-amber'}>
                {c.matches_router ? 'same maker as your router' : 'different maker — check it is yours'}
              </span>
            </label>
          ))}
          {data.not_heard.length > 0 && (
            <div className="text-[9px] text-text-muted">
              Not heard yet: {data.not_heard.join(', ')}. The adapter sweeps the channels every few seconds, so try
              again in a minute.
            </div>
          )}
          <button
            type="button"
            onClick={() =>
              onApply(
                data.protected_ssids,
                data.candidates.filter((c) => picked[c.bssid]).map((c) => c.bssid),
              )
            }
            disabled={data.protected_ssids.length === 0}
            className="border border-accent-green/30 bg-accent-green/5 px-2 py-1 text-[10px] tracking-wider text-accent-green hover:bg-accent-green/20 disabled:opacity-40"
          >
            USE THESE
          </button>
          <span className="ml-2 text-[9px] text-text-muted">Adds them to the lists below. Press SAVE to keep them.</span>
        </div>
      )}
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
        An "evil twin" is a fake access point that copies the name of your WiFi so devices connect to it
        instead of your router. This watches the airwaves and alerts when a network with one of your names
        is broadcast by hardware that is not yours. It needs a second, USB WiFi adapter that supports monitor
        mode (not the one your connection uses). See the WIFI tab.
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

          <DetectPanel
            onApply={(newSsids, newBssids) => {
              setSsids((cur) => [...cur, ...newSsids.filter((v) => !cur.includes(v))])
              setBssids((cur) => [...cur, ...newBssids.filter((v) => !cur.includes(v))])
            }}
          />

          <ChipList
            label="YOUR WIFI NAMES (PROTECTED SSIDS)"
            hint="The names of your own WiFi networks, as devices see them (for example the 2.4 GHz and the 5 GHz name)."
            placeholder="e.g. MyHomeWiFi"
            values={ssids}
            onChange={setSsids}
          />
          <ChipList
            label="YOUR ACCESS POINTS (TRUSTED BSSIDS)"
            hint="The hardware address of each WiFi radio that really belongs to you: your router and any extender. A network using your name from any other address is reported as a rogue access point."
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
