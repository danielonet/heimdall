import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../../lib/api'
import { StatusDot } from '../StatusDot'
import { MacAddress } from '../MacAddress'
import { Badge } from '../Badge'
import { BlockButton } from '../BlockButton'
import { UnblockButton } from '../UnblockButton'

export function DeviceHeader({ device }) {
  const qc = useQueryClient()

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

  return (
    <div className="border border-border bg-surface p-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <StatusDot variant={device.is_blocked ? 'red' : 'green'} pulse={!device.is_blocked} />
            <span className="font-heading text-lg font-semibold text-text-primary">
              {device.hostname || device.mac_address}
            </span>
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-1 text-[10px] text-text-secondary">
            <span>
              <MacAddress mac={device.mac_address} vendor={device.vendor_name} />
            </span>
            <span>{device.ip_address || '—'}</span>
            {device.vendor_name && <span>{device.vendor_name}</span>}
            {device.os_fingerprint && <span>{device.os_fingerprint}</span>}
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            <Badge variant="info">{device.interface_name === 'Ethernet' ? 'ETH' : 'WiFi'}</Badge>
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

        {device.is_blocked ? (
          <UnblockButton mac={device.mac_address} />
        ) : (
          <BlockButton mac={device.mac_address} />
        )}
      </div>
    </div>
  )
}
