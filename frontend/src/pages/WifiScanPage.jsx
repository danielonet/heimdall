import { useMarkSightingMine, useWifiNetworks, useWifiSightings } from '../hooks/useWifi'
import { useSettings, useUpdateSettings } from '../hooks/useSettings'
import { useNowTick } from '../hooks/useNowTick'
import { TimeAgo } from '../components/TimeAgo'
import { SignalBars } from '../components/SignalBars'
import { guessDeviceType, guessNetworkDevice } from '../lib/deviceGuess'
import { isSightingAccountedFor, isSightingInRange } from '../lib/wifiSightings'

// Read-only inventory — no filters in v1 (see docs/architecture/
// 13-wifi-monitor.md's scope cuts). A row here is NOT a Device: it's just
// something overheard via passive 802.11 monitoring, whether or not it's
// ever associated with this network — see sentinel/db/models.py:WifiSighting
// and WifiNetwork.

function KnownDeviceCell({ sighting }) {
  const kd = sighting.known_device
  if (sighting.is_mine) {
    return (
      <span className="text-accent-green" title="Marked as yours by hand">
        Yours (marked)
      </span>
    )
  }
  if (!kd) {
    return <span className="text-accent-amber">Never joined</span>
  }
  const how = kd.is_online ? (kd.interface_name === 'Ethernet' ? 'online, wired' : 'online') : 'offline'
  if (kd.match === 'exact') {
    return (
      <span className="text-accent-green" title="Same MAC as a device Heimdall already knows">
        Yours: {kd.name} ({how})
      </span>
    )
  }
  return (
    <span className="text-accent-green" title="Same manufacturer prefix as a known device — likely its WiFi adapter">
      Connected (probably {kd.name}&apos;s WiFi, {how})
    </span>
  )
}

function MineButton({ sighting }) {
  const mark = useMarkSightingMine()
  // Already accounted for some other way — no button needed.
  if (isSightingAccountedFor(sighting)) return null
  return (
    <button
      type="button"
      disabled={mark.isPending}
      onClick={() => mark.mutate({ mac: sighting.mac_address, isMine: true })}
      className="border border-border px-2 py-0.5 text-[9px] tracking-wider text-text-secondary hover:border-border-active disabled:opacity-40"
    >
      MARK AS MINE
    </button>
  )
}

function DevicesSection() {
  const { data: sightings, isLoading } = useWifiSightings()
  const now = useNowTick()

  // Out-of-range devices are dropped from view, not deleted — see
  // lib/wifiSightings.js (shared with the Network Map).
  const visible = (sightings || []).filter((s) => isSightingInRange(s, now))
  const outOfRangeCount = (sightings || []).length - visible.length

  return (
    <div className="border border-border bg-surface p-4">
      <div className="mb-1 flex items-baseline gap-2">
        <div className="text-[8px] tracking-[3px] text-text-muted">NEARBY WIFI DEVICES</div>
        {outOfRangeCount > 0 && (
          <div className="text-[9px] text-text-muted">
            {outOfRangeCount} more out of range (not heard in over a minute)
          </div>
        )}
      </div>
      <p className="mb-3 text-[10px] leading-relaxed text-text-secondary">
        MACs overheard broadcasting nearby via passive 802.11 monitoring, right now — a device drops off this
        list once it hasn&apos;t been heard from in over a minute. A device you already own can appear here
        too (its WiFi radio is on even if it&apos;s connected by cable) — the STATUS column says which.
        Requires a monitor-capable WiFi adapter configured under Settings &gt; WiFi Monitor.
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}
      {!isLoading && visible.length === 0 && (
        <div className="text-[10px] text-text-muted">
          {sightings && sightings.length > 0
            ? 'Nothing currently in range — everything last heard has been quiet for over a minute.'
            : "No sightings yet — either nothing has been overheard, or WiFi Monitor isn't configured."}
        </div>
      )}

      {!isLoading && visible.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[1180px] text-[10px]">
            <thead>
              <tr className="border-b border-border text-left text-text-muted">
                <th className="py-2 pr-4 font-normal tracking-wider">MAC ADDRESS</th>
                <th className="py-2 pr-4 font-normal tracking-wider">STATUS</th>
                <th className="py-2 pr-4 font-normal tracking-wider">VENDOR</th>
                <th className="py-2 pr-4 font-normal tracking-wider">LIKELY DEVICE</th>
                <th className="py-2 pr-4 font-normal tracking-wider">NETWORK</th>
                <th className="py-2 pr-4 font-normal tracking-wider">SIGNAL</th>
                <th className="py-2 pr-4 font-normal tracking-wider">STRONGEST</th>
                <th className="py-2 pr-4 font-normal tracking-wider">TIMES SEEN</th>
                <th className="py-2 pr-4 font-normal tracking-wider">FIRST SEEN</th>
                <th className="py-2 pr-4 font-normal tracking-wider">LAST SEEN</th>
                <th className="py-2 font-normal tracking-wider" />
              </tr>
            </thead>
            <tbody>
              {visible.map((s) => (
                <tr key={s.mac_address} className="border-b border-border/40 text-text-secondary">
                  <td className="py-2 pr-4 font-mono text-text-primary">{s.mac_address}</td>
                  <td className="py-2 pr-4">
                    <KnownDeviceCell sighting={s} />
                  </td>
                  <td className="py-2 pr-4">{s.vendor_name || '—'}</td>
                  <td className="py-2 pr-4">{guessDeviceType(s.vendor_name, s.mac_address)}</td>
                  <td className="py-2 pr-4" title="The WiFi network name this device last asked for">
                    {s.last_probed_ssid || '—'}
                  </td>
                  <td className="py-2 pr-4">
                    <SignalBars dbm={s.strongest_signal_dbm} />
                  </td>
                  <td className="py-2 pr-4">
                    {s.strongest_signal_dbm != null ? `${s.strongest_signal_dbm} dBm` : '—'}
                  </td>
                  <td className="py-2 pr-4">{s.times_seen}</td>
                  <td className="py-2 pr-4">
                    <TimeAgo iso={s.first_seen} />
                  </td>
                  <td className="py-2 pr-4">
                    <TimeAgo iso={s.last_seen} />
                  </td>
                  <td className="py-2">
                    <MineButton sighting={s} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

function NetworksSection() {
  const { data: networks, isLoading } = useWifiNetworks()
  const { data: settings } = useSettings()
  const update = useUpdateSettings()

  const mySsids = settings?.wifi_protected_ssids || []
  const myBssids = settings?.wifi_trusted_bssids || []

  // Trusting a BSSID and protecting its SSID is what makes the rogue-AP
  // check understand "this radio is mine" — see WifiMonitorWatcher._process.
  function markMine(n) {
    update.mutate({
      wifi_trusted_bssids: [...new Set([...myBssids, n.bssid])],
      ...(n.ssid ? { wifi_protected_ssids: [...new Set([...mySsids, n.ssid])] } : {}),
    })
  }

  return (
    <div className="mt-3 border border-border bg-surface p-4">
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">NEARBY WIFI NETWORKS</div>
      <p className="mb-3 text-[10px] leading-relaxed text-text-secondary">
        Routers and access points heard nearby — the same list your phone shows under Wi-Fi. One network
        often appears several times (2.4GHz, 5GHz, guest, mesh nodes), one row per radio. Mark your own so the
        rogue-AP check knows them.
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}
      {!isLoading && (!networks || networks.length === 0) && (
        <div className="text-[10px] text-text-muted">No networks heard yet.</div>
      )}

      {!isLoading && networks && networks.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full min-w-[1000px] text-[10px]">
            <thead>
              <tr className="border-b border-border text-left text-text-muted">
                <th className="py-2 pr-4 font-normal tracking-wider">NETWORK NAME</th>
                <th className="py-2 pr-4 font-normal tracking-wider">LIKELY DEVICE</th>
                <th className="py-2 pr-4 font-normal tracking-wider">BSSID</th>
                <th className="py-2 pr-4 font-normal tracking-wider">VENDOR</th>
                <th className="py-2 pr-4 font-normal tracking-wider">BAND / CH</th>
                <th className="py-2 pr-4 font-normal tracking-wider">SECURITY</th>
                <th className="py-2 pr-4 font-normal tracking-wider">SIGNAL</th>
                <th className="py-2 pr-4 font-normal tracking-wider">LAST SEEN</th>
                <th className="py-2 font-normal tracking-wider" />
              </tr>
            </thead>
            <tbody>
              {networks.map((n) => {
                const mine = myBssids.includes(n.bssid)
                return (
                  <tr key={n.bssid} className="border-b border-border/40 text-text-secondary">
                    <td className="py-2 pr-4 text-text-primary">{n.ssid || <span className="text-text-muted">(hidden)</span>}</td>
                    <td className="py-2 pr-4">{guessNetworkDevice(n.vendor_name, n.bssid)}</td>
                    <td className="py-2 pr-4 font-mono">{n.bssid}</td>
                    <td className="py-2 pr-4">{n.vendor_name || '—'}</td>
                    <td className="py-2 pr-4">
                      {n.channel ? `${n.channel > 14 ? '5G' : '2.4G'} · ch ${n.channel}` : '—'}
                    </td>
                    <td className={`py-2 pr-4 ${n.secured ? '' : 'text-accent-red'}`}>{n.secured ? 'Secured' : 'OPEN'}</td>
                    <td className="py-2 pr-4" title={n.strongest_signal_dbm != null ? `${n.strongest_signal_dbm} dBm` : ''}>
                      <SignalBars dbm={n.strongest_signal_dbm} />
                    </td>
                    <td className="py-2 pr-4">
                      <TimeAgo iso={n.last_seen} />
                    </td>
                    <td className="py-2">
                      {mine ? (
                        <span className="text-accent-green">MINE</span>
                      ) : (
                        <button
                          type="button"
                          disabled={update.isPending}
                          onClick={() => markMine(n)}
                          className="border border-border px-2 py-0.5 text-[9px] tracking-wider text-text-secondary hover:border-border-active disabled:opacity-40"
                        >
                          MARK AS MINE
                        </button>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export function WifiScanPage() {
  return (
    <div className="p-4">
      <DevicesSection />
      <NetworksSection />
    </div>
  )
}
