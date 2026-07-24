import { useState } from 'react'
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

  const filtered = filterDevices(devices || [], filters)

  const props = {
    devices: filtered,
    totalCount: devices?.length || 0,
    isLoading,
    filters,
    setFilters,
  }

  return mode === 'mobile' ? <MobileDevicesList {...props} /> : <DesktopDevicesList {...props} />
}
