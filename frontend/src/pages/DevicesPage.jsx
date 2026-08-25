import { useMemo, useState } from 'react'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { useDevices } from '../hooks/useDevices'
import { filterDevices } from '../lib/deviceFilters'
import { DesktopDevicesList } from './devices/DesktopDevicesList'
import { MobileDevicesList } from './devices/MobileDevicesList'

const DEFAULT_FILTERS = { search: '', connectivity: 'all', network: 'all', trust: 'all', presence: 'all' }

export function DevicesPage() {
  const mode = useLayoutMode()
  const { data: devices, isLoading } = useDevices()
  const [filters, setFilters] = useState(DEFAULT_FILTERS)

  // devices refetches every 15s (useDevices' refetchInterval) and every poll
  // hands back a new array reference even when nothing a user would notice
  // changed (traffic counters tick constantly). Without this memo, `filtered`
  // was a brand-new array on every one of those polls, forever, and got fed
  // straight into DesktopDevicesList's useReactTable as a new `data` prop
  // each time — needless churn on a page meant to be left open for hours.
  const filtered = useMemo(() => filterDevices(devices || [], filters), [devices, filters])

  const props = {
    devices: filtered,
    totalCount: devices?.length || 0,
    isLoading,
    filters,
    setFilters,
  }

  return mode === 'mobile' ? <MobileDevicesList {...props} /> : <DesktopDevicesList {...props} />
}
