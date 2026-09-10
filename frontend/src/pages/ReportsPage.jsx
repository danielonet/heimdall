import { useMemo, useState } from 'react'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { useReport } from '../hooks/useReports'
import { useDevices } from '../hooks/useDevices'
import { deviceDisplayName } from '../lib/deviceDisplay'
import { ReportAlertGroups } from '../components/reports/ReportAlertGroups'
import { ReportDeviceTraffic } from '../components/reports/ReportDeviceTraffic'
import { ReportDeviceTrafficChart } from '../components/reports/ReportDeviceTrafficChart'
import { ReportBandwidthChart } from '../components/reports/ReportBandwidthChart'

const HOUR_MS = 3600_000
const RANGE_PRESETS = [['24h', '24H', 24 * HOUR_MS], ['7d', '7D', 7 * 24 * HOUR_MS], ['30d', '30D', 30 * 24 * HOUR_MS]]

// datetime-local's value is local-time "YYYY-MM-DDTHH:mm", no timezone —
// Date's own toISOString() would convert to UTC and silently shift the
// displayed field, so this formats in the browser's own local time instead
// (the natural reading for "opens with the last 24h" — ending at whatever
// the visitor's own clock currently reads).
function toLocalInputValue(date) {
  const pad = (n) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

export function ReportsPage() {
  const mode = useLayoutMode()
  const { data: devices } = useDevices()

  const [endValue, setEndValue] = useState(() => toLocalInputValue(new Date()))
  const [startValue, setStartValue] = useState(() => toLocalInputValue(new Date(Date.now() - 24 * HOUR_MS)))
  const [deviceMac, setDeviceMac] = useState('')

  function applyPreset(rangeMs) {
    const now = new Date()
    setEndValue(toLocalInputValue(now))
    setStartValue(toLocalInputValue(new Date(now.getTime() - rangeMs)))
  }

  // Only re-derive the ISO strings (and thus refetch) when the local-time
  // input values actually change, not on every render.
  const start = useMemo(() => {
    const d = new Date(startValue)
    return Number.isNaN(d.getTime()) ? null : d.toISOString()
  }, [startValue])
  const end = useMemo(() => {
    const d = new Date(endValue)
    return Number.isNaN(d.getTime()) ? null : d.toISOString()
  }, [endValue])
  const rangeInvalid = start && end && start >= end

  const { data, isLoading, isError, error } = useReport({
    start: rangeInvalid ? null : start,
    end: rangeInvalid ? null : end,
    deviceMac: deviceMac || undefined,
  })

  const traffic = data?.traffic || []

  const filterGridClass = mode === 'mobile' ? 'grid grid-cols-1 gap-2' : 'flex flex-wrap items-end gap-3'

  return (
    <div className="space-y-3 p-3">
      <div className="border border-border bg-surface p-3">
        <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">REPORT WINDOW</div>
        <div className={filterGridClass}>
          <div>
            <label htmlFor="report-start" className="mb-1 block text-[9px] tracking-wider text-text-muted">
              FROM
            </label>
            <input
              id="report-start"
              type="datetime-local"
              value={startValue}
              onChange={(e) => setStartValue(e.target.value)}
              className="border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
            />
          </div>
          <div>
            <label htmlFor="report-end" className="mb-1 block text-[9px] tracking-wider text-text-muted">
              TO
            </label>
            <input
              id="report-end"
              type="datetime-local"
              value={endValue}
              onChange={(e) => setEndValue(e.target.value)}
              className="border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
            />
          </div>
          <div className="flex items-center gap-1">
            {RANGE_PRESETS.map(([key, text, ms]) => (
              <button
                key={key}
                type="button"
                onClick={() => applyPreset(ms)}
                className="border border-border px-2 py-1.5 text-[9px] tracking-wider text-text-muted transition-colors hover:text-text-secondary"
              >
                {text}
              </button>
            ))}
          </div>
          <div>
            <label htmlFor="report-device" className="mb-1 block text-[9px] tracking-wider text-text-muted">
              DEVICE
            </label>
            <select
              id="report-device"
              value={deviceMac}
              onChange={(e) => setDeviceMac(e.target.value)}
              className="w-56 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
            >
              <option value="">ALL DEVICES</option>
              {(devices || []).map((d) => (
                <option key={d.mac_address} value={d.mac_address}>
                  {deviceDisplayName(d)}
                </option>
              ))}
            </select>
          </div>
        </div>
        {rangeInvalid && <div className="mt-2 text-[9px] text-accent-red">FROM must be before TO.</div>}
      </div>

      {isLoading && <div className="p-4 text-center text-[10px] text-text-muted">Loading…</div>}
      {isError && <div className="border border-accent-red/30 bg-accent-red/5 p-3 text-[10px] text-accent-red">{error.message}</div>}

      {data && (
        <>
          <div className="border border-border bg-surface">
            <div className="border-b border-border/50 p-3 text-[8px] tracking-[3px] text-text-muted">
              ALERTS {deviceMac && '— THIS DEVICE'}
              {data.truncated && (
                <span className="ml-2 normal-case tracking-normal text-text-muted">
                  (showing {data.digest_groups.length} of {data.total_types} types)
                </span>
              )}
            </div>
            <ReportAlertGroups groups={data.digest_groups} total={data.total} severityCounts={data.severity_counts} />
          </div>

          <div className="border border-border bg-surface p-3">
            <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">
              BANDWIDTH BY HOUR <span className="normal-case tracking-normal text-text-muted">(household total)</span>
            </div>
            <ReportBandwidthChart hourlyBandwidth={data.hourly_bandwidth} />
          </div>

          <div className="border border-border bg-surface">
            <div className="border-b border-border/50 p-3 text-[8px] tracking-[3px] text-text-muted">
              DEVICE TRAFFIC {deviceMac && '— THIS DEVICE'}
            </div>
            <div className="p-3">
              <ReportDeviceTrafficChart traffic={traffic} />
            </div>
            <ReportDeviceTraffic traffic={traffic} />
          </div>
        </>
      )}
    </div>
  )
}
