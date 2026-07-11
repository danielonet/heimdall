import { useState } from 'react'
import { useThreatFeeds } from '../hooks/useThreatFeeds'
import { useIpLookup } from '../hooks/useIpLookup'
import { useLayoutMode } from '../hooks/useLayoutMode'
import { Badge } from '../components/Badge'
import { StatusDot } from '../components/StatusDot'
import { TimeAgo } from '../components/TimeAgo'

const FEED_LABELS = {
  feodo: 'Feodo Tracker (C2 IPs)',
  tor_exits: 'Tor Exit Nodes',
  spamhaus: 'Spamhaus DROP',
  urlhaus: 'URLhaus (malware URLs)',
}

export function ThreatsPage() {
  const { data: feeds, isLoading } = useThreatFeeds()
  const mode = useLayoutMode()
  const [ip, setIp] = useState('')
  const lookup = useIpLookup()

  // Keyed off layout mode, not viewport breakpoints — see PortsPage: ?mobile=1
  // can force the narrow shell on a wide browser, which sm:/xl: can't see.
  const gridClass = mode === 'mobile' ? 'grid grid-cols-1 gap-3' : 'grid grid-cols-2 gap-3 xl:grid-cols-4'

  function handleSubmit(e) {
    e.preventDefault()
    if (ip.trim()) lookup.mutate(ip.trim())
  }

  return (
    <div className="space-y-4 p-4">
      <div className="border border-border bg-surface p-4">
        <div className="mb-3 text-[8px] tracking-[3px] text-text-muted">THREAT INTEL FEEDS</div>
        {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}
        <div className={gridClass}>
          {Object.entries(feeds || {}).map(([name, info]) => (
            <div key={name} className="border border-border bg-bg p-3">
              <div className="mb-1 flex items-center gap-2">
                <StatusDot variant={info.error ? 'red' : info.refreshed_at ? 'green' : 'muted'} />
                <span className="text-[10px] text-text-primary">{FEED_LABELS[name] || name}</span>
              </div>
              <div className="text-[9px] text-text-secondary">{info.entry_count ?? 0} entries</div>
              <div className="text-[9px] text-text-muted">
                {info.refreshed_at ? (
                  <>
                    refreshed <TimeAgo iso={info.refreshed_at} />
                  </>
                ) : (
                  'never refreshed'
                )}
              </div>
              {info.error && <div className="mt-1 text-[9px] text-accent-red">{info.error}</div>}
            </div>
          ))}
          {!isLoading && Object.keys(feeds || {}).length === 0 && (
            <div className="text-[10px] text-text-muted">No feed data yet.</div>
          )}
        </div>
      </div>

      <div className="border border-border bg-surface p-4">
        <div className="mb-3 text-[8px] tracking-[3px] text-text-muted">IP REPUTATION LOOKUP</div>
        <form onSubmit={handleSubmit} className="flex gap-2">
          <input
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="e.g. 45.147.230.12"
            className="flex-1 border border-border bg-bg px-3 py-2 text-[11px] text-text-primary outline-none focus:border-border-active"
          />
          <button
            type="submit"
            disabled={lookup.isPending || !ip.trim()}
            className="border border-accent-green/40 bg-accent-green/10 px-4 py-2 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
          >
            {lookup.isPending ? '···' : 'LOOKUP'}
          </button>
        </form>

        {lookup.isError && <div className="mt-3 text-[10px] text-accent-red">{lookup.error.message}</div>}

        {lookup.isSuccess && (
          <div className="mt-3 border border-border bg-bg p-3 text-[10px]">
            <div className="mb-2 flex items-center gap-2">
              <span className="text-text-primary">{lookup.data.ip}</span>
              {lookup.data.is_malicious ? (
                <Badge variant="danger">MALICIOUS</Badge>
              ) : (
                <Badge variant="success">CLEAN</Badge>
              )}
            </div>
            <div className="text-text-secondary">
              In blocklist: {lookup.data.in_blocklist ? 'yes' : 'no'} · OTX pulses: {lookup.data.otx_pulses}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
