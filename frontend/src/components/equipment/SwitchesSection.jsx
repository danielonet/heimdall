import { useState } from 'react'
import { Badge } from '../Badge'
import { TimeAgo } from '../TimeAgo'
import { SwitchFormModal } from './SwitchFormModal'
import { SwitchPortsTable } from './SwitchPortsTable'
import { useRemoveSwitch, useSwitchCatalog, useSwitches, useTestSwitch } from '../../hooks/useSwitches'

function status(sw) {
  if (!sw.enabled) return { variant: 'muted', label: 'DISABLED' }
  if (sw.last_error) return { variant: 'danger', label: 'NOT REPORTING' }
  if (sw.last_ok_at) return { variant: 'success', label: 'REPORTING' }
  return { variant: 'info', label: 'WAITING FOR FIRST POLL' }
}

const BUTTON =
  'border border-accent-green/30 bg-accent-green/5 px-3 py-1 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40'

// Managed switches: pick a model from the catalog, give its address and login, and Heimdall reads each port's
// counters and the MAC table to show per-device traffic for devices that are alone on a port. The model list
// comes from GET /api/switches/catalog, so supporting another switch needs no change here.
export function SwitchesSection() {
  const { data: catalogData } = useSwitchCatalog()
  const { data: switches = [] } = useSwitches()
  const removeMutation = useRemoveSwitch()
  const testMutation = useTestSwitch()
  const [editing, setEditing] = useState(null) // null | 'new' | a switch row
  const [openPorts, setOpenPorts] = useState(null)
  const [testResult, setTestResult] = useState({})

  const catalog = catalogData?.switches || []
  const specById = Object.fromEntries(catalog.map((s) => [s.id, s]))
  const maxSwitches = catalogData?.max_switches ?? 5

  function runTest(sw) {
    testMutation.mutate(
      { id: sw.id },
      { onSuccess: (data) => setTestResult((r) => ({ ...r, [sw.id]: data })) },
    )
  }

  function remove(sw) {
    if (!window.confirm(`Stop monitoring ${sw.name} and forget its password and port history?`)) return
    removeMutation.mutate({ id: sw.id })
  }

  return (
    <div className="border border-border bg-surface p-3">
      <div className="mb-2 text-[8px] tracking-[3px] text-text-muted">SWITCHES</div>
      <p className="mb-2 text-[10px] leading-relaxed text-text-secondary">
        A router can only count wired traffic per port. A managed switch counts it on each of its own ports, so a
        device that is alone on a switch port gets its own upload and download here. Several devices behind one
        port (an uplink, an access point) stay a port total.
      </p>

      <ul className="space-y-1.5">
        {switches.map((sw) => {
          const st = status(sw)
          const spec = specById[sw.spec_id]
          const result = testResult[sw.id]
          return (
            <li key={sw.id} className="border border-border/60 px-3 py-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <div className="min-w-48 flex-1">
                  <div className="text-[11px] text-text-primary">{sw.name}</div>
                  <div className="text-[9px] text-text-muted">
                    {spec?.label || sw.spec_id} · {sw.host}
                    {sw.model ? ` · ${sw.model}` : ''}
                    {sw.firmware ? ` ${sw.firmware}` : ''}
                    {sw.last_ok_at && (
                      <>
                        {' · last read '}
                        <TimeAgo iso={sw.last_ok_at} />
                      </>
                    )}
                  </div>
                </div>
                <Badge variant={st.variant}>{st.label}</Badge>
                {spec && (
                  <Badge
                    variant={spec.tested ? 'success' : 'muted'}
                    title={spec.tested ? 'Run against this model of switch' : 'Checked against captured pages, not yet against real hardware'}
                  >
                    {spec.tested ? 'TESTED' : 'NOT YET TESTED ON HARDWARE'}
                  </Badge>
                )}
                <button type="button" className={BUTTON} onClick={() => setOpenPorts(openPorts === sw.id ? null : sw.id)}>
                  {openPorts === sw.id ? 'HIDE PORTS' : 'PORTS'}
                </button>
                <button type="button" className={BUTTON} disabled={testMutation.isPending} onClick={() => runTest(sw)}>
                  TEST
                </button>
                <button type="button" className={BUTTON} onClick={() => setEditing(sw)}>
                  EDIT
                </button>
                <button
                  type="button"
                  className="border border-accent-red/30 bg-accent-red/5 px-3 py-1 text-[10px] tracking-wider text-accent-red hover:bg-accent-red/20"
                  onClick={() => remove(sw)}
                >
                  REMOVE
                </button>
              </div>
              {sw.last_error && sw.enabled && (
                <div role="alert" className="mt-1 text-[9px] text-accent-red">
                  {sw.last_error}
                </div>
              )}
              {result && (
                <div
                  className={`mt-1 text-[9px] ${result.ok ? 'text-accent-green' : 'text-accent-red'}`}
                  role={result.ok ? 'status' : 'alert'}
                >
                  {result.ok
                    ? `✓ Signed in · ${result.ports_up} of ${result.ports} ports up · ${result.macs} devices seen · ${result.single_device_ports.length} port${result.single_device_ports.length === 1 ? '' : 's'} with exactly one device`
                    : `✗ ${result.error}`}
                </div>
              )}
              {openPorts === sw.id && <SwitchPortsTable id={sw.id} />}
            </li>
          )
        })}
      </ul>
      {removeMutation.isError && <div className="mt-2 text-[9px] text-accent-red">{removeMutation.error.message}</div>}

      <button
        type="button"
        className={`${BUTTON} mt-3`}
        disabled={switches.length >= maxSwitches || catalog.every((s) => !s.implemented)}
        onClick={() => setEditing('new')}
      >
        + ADD A SWITCH
      </button>
      {switches.length >= maxSwitches && (
        <span className="ml-2 text-[9px] text-text-muted">At most {maxSwitches} switches can be monitored.</span>
      )}

      {editing && (
        <SwitchFormModal
          catalog={catalog}
          current={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
        />
      )}
    </div>
  )
}
