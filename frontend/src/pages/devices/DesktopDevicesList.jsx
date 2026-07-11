import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { flexRender, getCoreRowModel, getSortedRowModel, useReactTable } from '@tanstack/react-table'
import { StatusDot } from '../../components/StatusDot'
import { MacAddress } from '../../components/MacAddress'
import { TrafficDisplay } from '../../components/TrafficDisplay'
import { Badge } from '../../components/Badge'
import { BlockButton } from '../../components/BlockButton'
import { UnblockButton } from '../../components/UnblockButton'
import { isDeviceOnline } from '../../lib/deviceFilters'

const FILTER_GROUPS = [
  { key: 'connectivity', options: [['all', 'ALL'], ['online', 'ONLINE'], ['offline', 'OFFLINE']] },
  { key: 'network', options: [['all', 'ALL'], ['wifi', 'WIFI'], ['wired', 'WIRED']] },
  { key: 'trust', options: [['all', 'ALL'], ['trusted', 'TRUSTED'], ['suspect', 'SUSPECT']] },
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
    header: 'HOSTNAME',
    accessorFn: (d) => d.hostname || d.mac_address,
    cell: ({ row }) => {
      const d = row.original
      return (
        <div className="min-w-0">
          <div className="truncate text-text-primary">{d.hostname || <MacAddress mac={d.mac_address} />}</div>
          <div className="truncate text-[9px] text-text-muted">{d.ip_address || '—'}</div>
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
    id: 'traffic',
    header: 'TRAFFIC',
    cell: ({ row }) => <TrafficDisplay sample={row.original.latest_traffic} />,
  },
  {
    id: 'type',
    header: 'TYPE',
    accessorFn: (d) => d.interface_name || '',
    cell: ({ getValue }) => <Badge variant="info">{getValue() === 'Ethernet' ? 'ETH' : 'WiFi'}</Badge>,
  },
  {
    id: 'trust',
    header: 'TRUST',
    accessorFn: (d) => (d.is_trusted ? 1 : 0),
    cell: ({ row }) =>
      row.original.is_trusted ? (
        <Badge variant="success">TRUSTED</Badge>
      ) : (
        <Badge variant="warning">SUSPECT</Badge>
      ),
  },
  {
    id: 'actions',
    header: 'ACTION',
    cell: ({ row }) => (
      <div onClick={(e) => e.stopPropagation()}>
        {row.original.is_blocked ? (
          <UnblockButton mac={row.original.mac_address} />
        ) : (
          <BlockButton mac={row.original.mac_address} />
        )}
      </div>
    ),
  },
]

export function DesktopDevicesList({ devices, totalCount, isLoading, filters, setFilters }) {
  const navigate = useNavigate()
  const [sorting, setSorting] = useState([])
  const columns = useMemo(() => columnHelperDefs, [])

  const table = useReactTable({
    data: devices,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
  })

  return (
    <div className="p-4">
      <div className="mb-4 flex flex-wrap items-center gap-4 border border-border bg-surface p-3">
        <input
          value={filters.search}
          onChange={(e) => setFilters((f) => ({ ...f, search: e.target.value }))}
          placeholder="Search hostname / IP / MAC…"
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
            {table.getRowModel().rows.map((row) => (
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
          </tbody>
        </table>
      </div>
    </div>
  )
}
