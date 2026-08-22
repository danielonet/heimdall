import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../../lib/api'
import { deviceDisplayName, isLocallyAdministeredMac } from '../../lib/deviceDisplay'
import { StatusDot } from '../StatusDot'
import { MacAddress } from '../MacAddress'
import { Badge } from '../Badge'
import { BlockButton } from '../BlockButton'
import { UnblockButton } from '../UnblockButton'
import { QuarantineButton } from '../QuarantineButton'
import { UnquarantineButton } from '../UnquarantineButton'

// device.blocked_until is only set for auto-blocks (see
// SentinelScheduler._raise_threat_alert/_block_expiry_job) — manual blocks
// stay indefinite (NULL) and render nothing extra here.
function autoUnblockLabel(blockedUntil) {
  const ms = new Date(blockedUntil).getTime() - Date.now()
  if (ms <= 0) return 'auto-unblocking shortly'
  const hours = Math.floor(ms / 3_600_000)
  const minutes = Math.floor((ms % 3_600_000) / 60_000)
  return `auto-unblocks in ${hours}h ${minutes}m`
}

export function DeviceHeader({ device }) {
  const qc = useQueryClient()
  const [renaming, setRenaming] = useState(false)
  const [nicknameDraft, setNicknameDraft] = useState(device.nickname || '')

  // nickname is durable — unlike hostname, nothing in the poll loop ever
  // overwrites it (see sentinel/db/models.py:Device.nickname). Submitting
  // an empty value clears it back to following the router-reported hostname.
  const setNickname = useMutation({
    mutationFn: (nickname) =>
      apiJson(`/devices/${device.mac_address}`, {
        method: 'PATCH',
        body: JSON.stringify({ nickname }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['devices'] })
      qc.invalidateQueries({ queryKey: ['device', device.mac_address] })
      setRenaming(false)
    },
  })

  const setTrusted = useMutation({
    mutationFn: (is_trusted) =>
      apiJson(`/devices/${device.mac_address}`, {
        method: 'PATCH',
        body: JSON.stringify({ is_trusted }),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['devices'] })
      qc.invalidateQueries({ queryKey: ['device', device.mac_address] })
    },
  })

  // A device auto-linked as a stale duplicate (see DeviceRepository.link()
  // / sentinel/detection/device_identity.py — a phone's randomized WiFi MAC
  // reconnecting under a new address) can be wrongly linked; UNLINK is the
  // way back, same "automatic action needs a manual undo" shape as
  // AckResolveButtons' REOPEN.
  const unlink = useMutation({
    mutationFn: () => apiJson(`/devices/${device.mac_address}/unlink`, { method: 'POST' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['devices'] })
      qc.invalidateQueries({ queryKey: ['device', device.mac_address] })
    },
  })

  return (
    <div className="border border-border bg-surface p-4">
      {device.linked_to_mac && (
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2 border border-accent-amber/30 bg-accent-amber/5 px-3 py-2">
          <span className="text-[10px] text-accent-amber">
            Linked to{' '}
            <Link to={`/devices/${device.linked_to_mac}`} className="underline hover:text-text-primary">
              {device.linked_to_hostname || device.linked_to_mac}
            </Link>{' '}
            — hidden from device lists as a stale duplicate.
          </span>
          <button
            type="button"
            disabled={unlink.isPending}
            onClick={() => unlink.mutate()}
            className="whitespace-nowrap border border-accent-amber/30 bg-accent-amber/5 px-2 py-0.5 text-[9px] tracking-wider text-accent-amber transition-colors hover:bg-accent-amber/20 disabled:opacity-50"
          >
            UNLINK
          </button>
        </div>
      )}
      {device.linked_into?.length > 0 && (
        <div className="mb-3 border border-border bg-surface-elevated px-3 py-2 text-[10px] text-text-secondary">
          {device.linked_into.length} device{device.linked_into.length > 1 ? 's' : ''} linked into this one:{' '}
          {device.linked_into.map((d, i) => (
            <span key={d.mac_address}>
              {i > 0 && ', '}
              <Link to={`/devices/${d.mac_address}`} className="text-accent-blue underline hover:text-text-primary">
                {deviceDisplayName(d)}
              </Link>
            </span>
          ))}
        </div>
      )}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <StatusDot variant={device.is_blocked ? 'red' : 'green'} pulse={!device.is_blocked} />
            {renaming ? (
              <form
                className="flex items-center gap-1.5"
                onSubmit={(e) => {
                  e.preventDefault()
                  setNickname.mutate(nicknameDraft.trim())
                }}
              >
                <input
                  autoFocus
                  value={nicknameDraft}
                  onChange={(e) => setNicknameDraft(e.target.value)}
                  placeholder={device.hostname || device.mac_address}
                  className="border border-border bg-surface-elevated px-2 py-0.5 font-heading text-lg font-semibold text-text-primary outline-none focus:border-accent-blue"
                />
                <button
                  type="submit"
                  disabled={setNickname.isPending}
                  className="border border-accent-green/30 bg-accent-green/5 px-1.5 py-0.5 text-[9px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-50"
                >
                  SAVE
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setNicknameDraft(device.nickname || '')
                    setRenaming(false)
                  }}
                  className="border border-border px-1.5 py-0.5 text-[9px] tracking-wider text-text-muted transition-colors hover:bg-surface-elevated"
                >
                  CANCEL
                </button>
              </form>
            ) : (
              <span
                className="group flex cursor-pointer items-center gap-2"
                onClick={() => setRenaming(true)}
                title="Click to rename"
              >
                <span className="font-heading text-lg font-semibold text-text-primary">
                  {deviceDisplayName(device)}
                </span>
                <span className="text-[9px] tracking-wider text-text-muted opacity-0 transition-opacity group-hover:opacity-100">
                  ✎ RENAME
                </span>
              </span>
            )}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] text-text-secondary">
            <span>
              <MacAddress mac={device.mac_address} vendor={device.vendor_name} />
            </span>
            {device.nickname && device.hostname && (
              <span title="Router-reported hostname">router: {device.hostname}</span>
            )}
            <span>{device.ip_address || '—'}</span>
            {device.vendor_name && <span>{device.vendor_name}</span>}
            {!device.vendor_name && isLocallyAdministeredMac(device.mac_address) && (
              <span
                className="text-text-muted"
                title="This MAC is randomized (WiFi private address / per-network randomization) — there's no real manufacturer OUI to look up"
              >
                Private address
              </span>
            )}
            {device.device_type && device.device_type !== 'MISCELLANEOUS' && <span>{device.device_type}</span>}
            {device.os_fingerprint && <span>{device.os_fingerprint}</span>}
            {device.is_blocked && device.blocked_until && (
              <span className="text-accent-amber">{autoUnblockLabel(device.blocked_until)}</span>
            )}
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            <Badge variant="info">
              {device.interface_name === 'Ethernet' ? `ETH${device.port_alias ? ` · ${device.port_alias}` : ''}` : 'WiFi'}
            </Badge>
            {device.ap_alias && (
              <Badge
                variant={device.ap_alias.startsWith('GUEST') ? 'warning' : 'info'}
                title="Which access point this device is associated with"
              >
                {device.ap_alias}
              </Badge>
            )}
            {device.is_quarantined && (
              <Badge variant="warning" title="Internet access cut, still reachable on the LAN">
                QUARANTINED
              </Badge>
            )}
            <button
              type="button"
              disabled={setTrusted.isPending}
              onClick={() => setTrusted.mutate(!device.is_trusted)}
              title={device.is_trusted ? 'Click to mark as untrusted' : 'Click to mark as trusted'}
              className={`whitespace-nowrap border px-1.5 py-0.5 text-[9px] tracking-wider transition-colors disabled:opacity-50 ${
                device.is_trusted
                  ? 'border-accent-green/30 bg-accent-green/5 text-accent-green hover:bg-accent-green/20'
                  : 'border-accent-amber/30 bg-accent-amber/5 text-accent-amber hover:bg-accent-amber/20'
              }`}
            >
              {device.is_trusted ? 'TRUSTED' : 'SUSPECT'}
            </button>
            {(device.tags || []).map((tag) => (
              <Badge key={tag} variant="info">
                {tag}
              </Badge>
            ))}
          </div>
        </div>

        <div className="flex flex-shrink-0 items-center gap-1.5">
          {device.is_quarantined ? (
            <UnquarantineButton mac={device.mac_address} />
          ) : (
            <QuarantineButton mac={device.mac_address} disabled={device.is_blocked} />
          )}
          {device.is_blocked ? (
            <UnblockButton mac={device.mac_address} />
          ) : (
            <BlockButton mac={device.mac_address} />
          )}
        </div>
      </div>
    </div>
  )
}
