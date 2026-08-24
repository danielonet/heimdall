import { useState } from 'react'
import { Link } from 'react-router-dom'
import { usePortAllowlist, useAllowPort, useDisallowPort } from '../../hooks/usePortAllowlist'
import { useDevices } from '../../hooks/useDevices'
import { deviceDisplayName } from '../../lib/deviceDisplay'

const SELECT_CLASS = 'border border-border bg-bg px-2 py-1 text-[10px] text-text-primary outline-none focus:border-border-active'
const INPUT_CLASS = SELECT_CLASS

function entryKey(mac, port) {
  return `${mac}:${port}`
}

function EntryRow({ entry, onRemove, isRemoving }) {
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-border/50 py-1.5 text-[10px] last:border-none">
      <div className="min-w-0 flex-1">
        <Link
          to={`/devices/${entry.device_mac}`}
          className="text-text-primary hover:text-accent-blue hover:underline"
        >
          {deviceDisplayName({ nickname: entry.nickname, hostname: entry.hostname, mac_address: entry.device_mac })}
        </Link>
        <div className="truncate text-[9px] text-text-muted">
          {entry.ip_address || '—'} · {entry.device_mac}
          {entry.is_blocked && <span className="ml-1.5 text-accent-red">BLOCKED</span>}
        </div>
      </div>
      <div className="w-14 flex-shrink-0 text-text-secondary">{entry.port}</div>
      <div className="w-20 flex-shrink-0 truncate text-text-secondary" title={entry.service}>
        {entry.service}
      </div>
      <div className="min-w-0 flex-[2] truncate text-[9px] text-text-muted" title={entry.note || ''}>
        {entry.note || '—'}
      </div>
      <button
        type="button"
        disabled={isRemoving}
        onClick={onRemove}
        className="flex-shrink-0 border border-border px-2 py-1 text-[9px] tracking-wider text-text-muted transition-colors hover:text-accent-red disabled:opacity-40"
      >
        {isRemoving ? '···' : 'REMOVE'}
      </button>
    </div>
  )
}

function AddEntryForm({ devices, highRiskPorts, existingKeys, onAdd, isSaving }) {
  const [mac, setMac] = useState('')
  const [port, setPort] = useState('')
  const [note, setNote] = useState('')

  const alreadyAllowed = mac && port && existingKeys.has(entryKey(mac, port))
  const canAdd = mac !== '' && port !== '' && !alreadyAllowed

  function handleAdd() {
    onAdd({ mac, port: Number(port), note: note.trim() })
    setMac('')
    setPort('')
    setNote('')
  }

  return (
    <div className="flex flex-wrap items-center gap-2 border-t border-border pt-2 text-[10px]">
      <select value={mac} onChange={(e) => setMac(e.target.value)} className={`${SELECT_CLASS} min-w-[10rem]`}>
        <option value="">select device…</option>
        {devices.map((d) => (
          <option key={d.mac_address} value={d.mac_address}>
            {deviceDisplayName(d)} ({d.mac_address})
          </option>
        ))}
      </select>
      <select value={port} onChange={(e) => setPort(e.target.value)} className={`${SELECT_CLASS} w-32`}>
        <option value="">select port…</option>
        {highRiskPorts.map((p) => (
          <option key={p.port} value={p.port}>
            {p.port} ({p.service})
          </option>
        ))}
      </select>
      <input
        type="text"
        placeholder="note (optional)"
        value={note}
        onChange={(e) => setNote(e.target.value)}
        className={`${INPUT_CLASS} min-w-[10rem] flex-1`}
      />
      <button
        type="button"
        disabled={!canAdd || isSaving}
        onClick={handleAdd}
        className="flex-shrink-0 border border-accent-green/30 bg-accent-green/5 px-2 py-1 text-[9px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
      >
        {isSaving ? '···' : 'ADD'}
      </button>
      {alreadyAllowed && <span className="w-full text-[9px] text-accent-amber">Already allowlisted.</span>}
    </div>
  )
}

/** Every (device, port) pair explicitly exempted from NetworkScanner's
 * HIGH_RISK_PORTS check (sentinel/security/scanner.py) — see
 * SentinelScheduler._nmap_scan_job. Once added, that port never raises
 * HIGH_RISK_PORT_OPENED (or triggers auto-block) on that device again. */
export function PortAllowlistSection() {
  const { data, isLoading } = usePortAllowlist()
  const { data: devices } = useDevices()
  const allowMutation = useAllowPort()
  const disallowMutation = useDisallowPort()
  const [pendingKey, setPendingKey] = useState(null)

  const entries = data?.allowlist || []
  const highRiskPorts = data?.high_risk_ports || []
  const existingKeys = new Set(entries.map((e) => entryKey(e.device_mac, e.port)))

  function add({ mac, port, note }) {
    setPendingKey(entryKey(mac, port))
    allowMutation.mutate({ mac, port, note }, { onSettled: () => setPendingKey(null) })
  }

  function remove(mac, port) {
    setPendingKey(entryKey(mac, port))
    disallowMutation.mutate({ mac, port }, { onSettled: () => setPendingKey(null) })
  }

  return (
    <div className="mt-4 border border-border bg-surface p-3">
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">PORT ALLOWLIST</div>
      <p className="mb-3 text-[10px] leading-relaxed text-text-secondary">
        A device/port pair added here is excluded from the nightly nmap scan's high-risk-port
        check for good — it stops raising HIGH_RISK_PORT_OPENED (and triggering auto-block) on
        that device and port. Use it for a known-legitimate service that happens to run on a port
        this check treats as suspicious by default (e.g. a print server's SMB share on port 445).
        Adding an entry also resolves any currently-open finding for it and, if the device is
        currently auto-blocked because of it, unblocks it.
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && entries.length === 0 && (
        <div className="py-2 text-[10px] text-text-muted">No allowlisted ports yet.</div>
      )}

      {!isLoading &&
        entries.map((entry) => (
          <EntryRow
            key={entryKey(entry.device_mac, entry.port)}
            entry={entry}
            onRemove={() => remove(entry.device_mac, entry.port)}
            isRemoving={disallowMutation.isPending && pendingKey === entryKey(entry.device_mac, entry.port)}
          />
        ))}

      {!isLoading && (
        <AddEntryForm
          devices={devices || []}
          highRiskPorts={highRiskPorts}
          existingKeys={existingKeys}
          onAdd={add}
          isSaving={allowMutation.isPending}
        />
      )}

      {allowMutation.isError && (
        <div className="mt-2 text-[9px] text-accent-red">{allowMutation.error.message}</div>
      )}
      {disallowMutation.isError && (
        <div className="mt-2 text-[9px] text-accent-red">{disallowMutation.error.message}</div>
      )}
      {allowMutation.isSuccess && allowMutation.data?.unblocked && (
        <div className="mt-2 text-[9px] text-accent-green">
          Device was auto-blocked over this finding — unblocked.
        </div>
      )}
    </div>
  )
}
