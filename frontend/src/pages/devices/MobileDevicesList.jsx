import { useNavigate } from 'react-router-dom'
import { StatusDot } from '../../components/StatusDot'
import { MacAddress } from '../../components/MacAddress'
import { TrafficDisplay } from '../../components/TrafficDisplay'
import { Badge } from '../../components/Badge'
import { SignalBars } from '../../components/SignalBars'
import { NeverConnectedIcon } from '../../components/NeverConnectedIcon'
import { BlockButton } from '../../components/BlockButton'
import { UnblockButton } from '../../components/UnblockButton'
import { isDeviceOnline } from '../../lib/deviceFilters'

const CHIP_GROUPS = [
  { key: 'connectivity', options: [['all', 'ALL'], ['online', 'ONLINE'], ['offline', 'OFFLINE']] },
  { key: 'network', options: [['all', 'ALL'], ['wifi', 'WIFI'], ['wired', 'WIRED']] },
  { key: 'trust', options: [['all', 'ALL'], ['trusted', 'TRUSTED'], ['suspect', 'SUSPECT']] },
  { key: 'presence', options: [['all', 'ALL'], ['connected', 'CONNECTED'], ['nearby', 'NEARBY ONLY']] },
]

export function MobileDevicesList({ devices, totalCount, isLoading, filters, setFilters }) {
  const navigate = useNavigate()

  return (
    <div className="space-y-3">
      <input
        value={filters.search}
        onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
        placeholder="Search hostname / IP / MAC…"
        className="w-full border border-border bg-surface px-3 py-2 text-[11px] text-text-primary outline-none focus:border-border-active"
      />

      <div className="flex flex-col gap-1.5">
        {CHIP_GROUPS.map((group) => (
          <div key={group.key} className="flex gap-1.5 overflow-x-auto">
            {group.options.map(([val, text]) => (
              <button
                key={val}
                type="button"
                onClick={() => setFilters((f) => ({ ...f, [group.key]: val }))}
                className={`flex-shrink-0 whitespace-nowrap border px-2 py-1 text-[9px] tracking-wider ${
                  filters[group.key] === val
                    ? 'border-accent-green/40 bg-accent-green/10 text-accent-green'
                    : 'border-border text-text-muted'
                }`}
              >
                {text}
              </button>
            ))}
          </div>
        ))}
      </div>

      <div className="text-[9px] tracking-wide text-text-muted">
        {devices.length} / {totalCount} DEVICES
      </div>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}
      {!isLoading && devices.length === 0 && (
        <div className="text-[10px] text-text-muted">No devices match these filters.</div>
      )}

      <div>
        {devices.map((d) => (
          <div
            key={d.mac_address}
            onClick={() => navigate(`/devices/${d.mac_address}`)}
            className="flex items-center gap-2 border-b border-border/50 py-2.5 last:border-none"
          >
            <StatusDot variant={d.is_blocked ? 'red' : isDeviceOnline(d) ? 'green' : 'muted'} />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5">
                {!d.ever_connected && <NeverConnectedIcon />}
                <div className="truncate text-[11px] text-text-primary">
                  {d.hostname || <MacAddress mac={d.mac_address} />}
                </div>
              </div>
              <div className="truncate text-[9px] text-text-muted">
                {d.ip_address || '—'}
                {d.device_type && d.device_type !== 'MISCELLANEOUS' && ` · ${d.device_type}`}
              </div>
            </div>
            <div className="flex flex-shrink-0 flex-col items-end gap-1">
              <TrafficDisplay sample={d.latest_traffic} />
              <div className="flex items-center gap-1">
                {d.interface_name === 'Ethernet' ? (
                  d.port_alias && <Badge variant="info">{d.port_alias}</Badge>
                ) : (
                  <SignalBars dbm={d.signal_strength_dbm} />
                )}
                <Badge variant="info">{d.interface_name === 'Ethernet' ? 'ETH' : 'WiFi'}</Badge>
                {d.is_trusted ? (
                  <Badge variant="success">OK</Badge>
                ) : (
                  <Badge variant="warning">SUS</Badge>
                )}
              </div>
              <div onClick={(e) => e.stopPropagation()}>
                {d.is_blocked ? <UnblockButton mac={d.mac_address} /> : <BlockButton mac={d.mac_address} />}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
