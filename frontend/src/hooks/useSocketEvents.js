import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { socket } from '../lib/socket'

// port:update's payload is the adapter's PortStats dataclass, not
// port_stats_to_dict() — same data, different field names for the delta
// counters and timestamp. Rename onto the REST shape so PortSummary/PortsPage
// only ever read one vocabulary regardless of where the update came from.
function normalizePortSnapshot(payload) {
  const { timestamp, sent_delta, recv_delta, ...rest } = payload
  return {
    ...rest,
    time: timestamp,
    bytes_sent_delta: sent_delta,
    bytes_recv_delta: recv_delta,
  }
}

function mergeByKey(list, patch, key) {
  return list.map((item) => (item[key] === patch[key] ? { ...item, ...patch } : item))
}

/** Wires the 5 socket events this stage's pages actually consume.
 * wan:status / ml:trained have no consumer yet — add handlers when a page
 * needs them instead of invalidating queries nothing reads. */
export function useSocketEvents() {
  const qc = useQueryClient()

  useEffect(() => {
    const onAlert = () => qc.invalidateQueries({ queryKey: ['alerts'] })

    const onDeviceUpdate = (patch) => {
      qc.setQueryData(['devices'], (old) =>
        old ? { ...old, devices: mergeByKey(old.devices, patch, 'mac_address') } : old,
      )
      qc.setQueryData(['device', patch.mac_address], (old) => (old ? { ...old, ...patch } : old))
    }

    const onDeviceJoined = () => qc.invalidateQueries({ queryKey: ['devices'] })

    const onPortUpdate = (payload) => {
      const patch = normalizePortSnapshot(payload)
      qc.setQueryData(['ports'], (old) => {
        if (!old) return old
        const exists = old.ports.some((p) => p.port_alias === patch.port_alias)
        const ports = exists
          ? mergeByKey(old.ports, patch, 'port_alias')
          : [...old.ports, patch]
        return { ...old, ports }
      })
    }

    const onFeedRefresh = () => qc.invalidateQueries({ queryKey: ['threat-feeds'] })

    socket.on('alert:new', onAlert)
    socket.on('device:update', onDeviceUpdate)
    socket.on('device:joined', onDeviceJoined)
    socket.on('port:update', onPortUpdate)
    socket.on('feed:refresh', onFeedRefresh)

    return () => {
      socket.off('alert:new', onAlert)
      socket.off('device:update', onDeviceUpdate)
      socket.off('device:joined', onDeviceJoined)
      socket.off('port:update', onPortUpdate)
      socket.off('feed:refresh', onFeedRefresh)
    }
  }, [qc])
}
