import { Fragment, useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { flexRender, getCoreRowModel, getSortedRowModel, useReactTable } from '@tanstack/react-table'
import { StatusDot } from '../../components/StatusDot'
import { MacAddress } from '../../components/MacAddress'
import { TrafficDisplay } from '../../components/TrafficDisplay'
import { Badge } from '../../components/Badge'
import { SignalBars } from '../../components/SignalBars'
import { NeverConnectedIcon } from '../../components/NeverConnectedIcon'
import { DeviceStatusSelect, deviceStatus } from '../../components/DeviceStatusSelect'
import { isDeviceOnline } from '../../lib/deviceFilters'
import { deviceDisplayName } from '../../lib/deviceDisplay'
import { groupByAp, isGuestApGroup } from '../../lib/apGroups'

const FILTER_GROUPS = [
  { key: 'connectivity', options: [['all', 'ALL'], ['online', 'ONLINE'], ['offline', 'OFFLINE']] },
  { key: 'network', options: [['all', 'ALL'], ['wifi', 'WIFI'], ['wired', 'WIRED']] },
  { key: 'trust', options: [['all', 'ALL'], ['trusted', 'TRUSTED'], ['suspect', 'SUSPECT']] },
  { key: 'presence', options: [['all', 'ALL'], ['connected', 'CONNECTED'], ['nearby', 'NEARBY ONLY']] },
]

function FilterGroup({ label, options, value, onChange }) {
  return (
    <div className="flex items-center gap-1">
      <span className="mr-1 text-[9px] tracking-wider text-text-muted">{label}</span>
      {options.map(([val, text]) => (
        <button
          key={val}
          type="button"
          onClick={() => onChange(val)}
          className={`border px-2 py-1 text-[9px] tracking-wider transition-colors ${
            value === val
              ? 'border-accent-green/40 bg-accent-green/10 text-accent-green'
              : 'border-border text-text-muted hover:text-text-secondary'
          }`}
        >
          {text}
        </button>
      ))}
    </div>
  )
}

const columnHelperDefs = [
  {
    id: 'status',
    header: '',
    cell: ({ row }) => (
      <StatusDot variant={row.original.is_blocked ? 'red' : isDeviceOnline(row.original) ? 'green' : 'muted'} />
    ),
  },
  {
    id: 'device',
    header: 'DEVICE',
    accessorFn: (d) => deviceDisplayName(d),
    cell: ({ row }) => {
      const d = row.original
      return (
        <div className="flex min-w-0 items-center gap-1.5">
          {!d.ever_connected && <NeverConnectedIcon />}
          <div className="min-w-0">
            <div className="truncate text-text-primary">
              {d.nickname || d.hostname || <MacAddress mac={d.mac_address} />}
            </div>
            <div className="truncate text-[9px] text-text-muted">{d.ip_address || '—'}</div>
          </div>
        </div>
      )
    },
  },
  {
    id: 'vendor',
    header: 'VENDOR',
    accessorFn: (d) => d.vendor_name || '',
    cell: ({ getValue }) => <span className="text-text-secondary">{getValue() || '—'}</span>,
  },
  {
    id: 'kind',
    header: 'KIND',
    // Router's own DHCP-fingerprint classification — 'MISCELLANEOUS' is the
    // router's own default when it couldn't identify the device, same as no
    // classification at all, so both render as '—'.
    accessorFn: (d) => (d.device_type && d.device_type !== 'MISCELLANEOUS' ? d.device_type : ''),
    cell: ({ getValue }) => <span className="text-text-secondary">{getValue() || '—'}</span>,
  },
  {
    id: 'traffic',
    header: 'TRAFFIC',
    cell: ({ row }) => <TrafficDisplay sample={row.original.latest_traffic} />,
  },
  {
    id: 'type',
    header: 'TYPE',
    accessorFn: (d) => d.interface_name || '',
    cell: ({ row, getValue }) => (
      <div className="flex flex-wrap gap-1">
        <Badge variant="info">{getValue() === 'Ethernet' ? 'ETH' : 'WiFi'}</Badge>
        {row.original.ap_alias && (
          <Badge
            variant={row.original.ap_alias.startsWith('GUEST') ? 'warning' : 'info'}
            title="Which access point this device is associated with"
          >
            {row.original.ap_alias}
          </Badge>
        )}
        {/* Only badged once a second router is actually configured — the
            common single-router (Sagemcom-only) case stays unbadged, same
            "don't show it unless it's meaningful" rule as ap_alias above. */}
        {row.original.source_router === 'miwifi' && (
          <Badge variant="muted" title="Reported by the Redmi router, not the Sagemcom">
            REDMI
          </Badge>
        )}
      </div>
    ),
  },
  {
    id: 'signal',
    header: 'SIGNAL / PORT',
    accessorFn: (d) => (d.interface_name === 'Ethernet' ? 0 : d.signal_strength_dbm || -999),
    cell: ({ row }) => {
      const d = row.original
      if (d.interface_name === 'Ethernet') {
        return d.port_alias ? (
          <Badge variant="info">{d.port_alias}</Badge>
        ) : (
          <span className="text-text-muted">—</span>
        )
      }
      return <SignalBars dbm={d.signal_strength_dbm} />
    },
  },
  {
    id: 'status',
    header: 'STATUS',
    accessorFn: (d) => deviceStatus(d),
    cell: ({ row }) => <DeviceStatusSelect device={row.original} />,
  },
]

export function DesktopDevicesList({ devices, totalCount, isLoading, filters, setFilters }) {
  const navigate = useNavigate()
  const [sorting, setSorting] = useState([])
  const [apGrouping, setApGrouping] = useState(false)
  const columns = useMemo(() => columnHelperDefs, [])

  const table = useReactTable({
    data: devices,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  })

  const rows = table.getRowModel().rows
  // Grouping is purely a presentation split of the already-sorted/filtered
  // rows — sorting still applies within each group, it just doesn't reorder
  // rows across groups.
  const rowGroups = apGrouping ? groupByAp(rows, (row) => row.original) : null

  return (
    <div className="p-4">
      <div className="mb-4 flex flex-wrap items-center gap-4 border border-border bg-surface p-3">
        <input
          value={filters.search}
          onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
          placeholder="Search name / IP / MAC…"
          className="w-56 border border-border bg-bg px-2 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
        />
        {FILTER_GROUPS.map((group) => (
          <FilterGroup
            key={group.key}
            label={group.key.toUpperCase()}
            options={group.options}
            value={filters[group.key]}
            onChange={(val) => setFilters((f) => ({ ...f, [group.key]: val }))}
          />
        ))}
        <button
          type="button"
          onClick={() => setApGrouping((g) => !g)}
          title="Group devices by which access point they're on"
          className={`border px-2 py-1 text-[9px] tracking-wider transition-colors ${
            apGrouping
              ? 'border-accent-green/40 bg-accent-green/10 text-accent-green'
              : 'border-border text-text-muted hover:text-text-secondary'
          }`}
        >
          GROUP BY AP
        </button>
        <span className="ml-auto text-[9px] tracking-wide text-text-muted">
          {devices.length} / {totalCount} DEVICES
        </span>
      </div>

      <div className="border border-border bg-surface">
        <table className="w-full border-collapse text-[11px]">
          <thead>
            {table.getHeaderGroups().map((hg) => (
              <tr key={hg.id} className="border-b border-border">
                {hg.headers.map((header) => (
                  <th
                    key={header.id}
                    onClick={header.column.getToggleSortingHandler()}
                    className="cursor-pointer px-3 py-2 text-left text-[9px] tracking-[2px] text-text-muted"
                  >
                    {flexRender(header.column.columnDef.header, header.getContext())}
                    {{ asc: ' ▲', desc: ' ▼' }[header.column.getIsSorted()] || ''}
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {isLoading && (
              <tr>
                <td colSpan={columns.length} className="p-4 text-center text-text-muted">
                  Loading…
                </td>
              </tr>
            )}
            {!isLoading && devices.length === 0 && (
              <tr>
                <td colSpan={columns.length} className="p-4 text-center text-text-muted">
                  No devices match these filters.
                </td>
              </tr>
            )}
            {!apGrouping &&
              rows.map((row) => (
                <tr
                  key={row.id}
                  onClick={() => navigate(`/devices/${row.original.mac_address}`)}
                  className="cursor-pointer border-b border-border/50 last:border-none hover:bg-border/20"
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-3 py-2">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
            {apGrouping &&
              rowGroups.map(([label, groupRows]) => (
                <Fragment key={label}>
                  <tr className="border-b border-border bg-bg/60">
                    <td
                      colSpan={columns.length}
                      className={`px-3 py-1.5 text-[9px] tracking-[2px] ${
                        isGuestApGroup(label) ? 'text-accent-amber' : 'text-text-muted'
                      }`}
                    >
                      {label} · {groupRows.length}
                    </td>
                  </tr>
                  {groupRows.map((row) => (
                    <tr
                      key={row.id}
                      onClick={() => navigate(`/devices/${row.original.mac_address}`)}
                      className="cursor-pointer border-b border-border/50 last:border-none hover:bg-border/20"
                    >
                      {row.getVisibleCells().map((cell) => (
                        <td key={cell.id} className="px-3 py-2">
                          {flexRender(cell.column.columnDef.cell, cell.getContext())}
                        </td>
                      ))}
                    </tr>
                  ))}
                </Fragment>
              ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
