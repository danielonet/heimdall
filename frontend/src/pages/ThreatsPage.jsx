import { useState } from 'react'
import { useThreatFeeds } from '../hooks/useThreatFeeds'
import { useImportUrlhausCsv, useRemoveUrlhausKey, useSaveUrlhausKey } from '../hooks/useUrlhausSetup'
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

const SOURCE_LABELS = {
  live: 'live feed',
  cache: 'saved copy (live refresh pending)',
  import: 'imported CSV',
}

// Self-service setup for the URLhaus feed: abuse.ch retired anonymous
// downloads, so the user creates a free key themselves and pastes it here (the
// backend stores it in secrets/abusech_auth_key.txt). "Later" is supported by
// importing a URLhaus CSV they already have — it is only a cache and is
// replaced as soon as a live refresh with a key succeeds.
function UrlhausSetup({ info }) {
  const [key, setKey] = useState('')
  const save = useSaveUrlhausKey()
  const remove = useRemoveUrlhausKey()
  const importCsv = useImportUrlhausCsv()

  if (info.key_configured) {
    return (
      <div className="mt-2 flex items-center gap-2 text-[9px] text-text-muted">
        <span>abuse.ch Auth-Key saved</span>
        <button
          type="button"
          onClick={() => remove.mutate()}
          disabled={remove.isPending}
          className="text-accent-red underline disabled:opacity-40"
        >
          remove
        </button>
        {remove.isError && <span className="text-accent-red">{remove.error.message}</span>}
      </div>
    )
  }

  function handleSave(e) {
    e.preventDefault()
    if (key.trim()) save.mutate(key.trim(), { onSuccess: () => setKey('') })
  }

  function handleFile(e) {
    const file = e.target.files?.[0]
    if (file) importCsv.mutate(file)
    e.target.value = ''
  }

  return (
    <div className="mt-2 border-t border-border/50 pt-2 text-[9px] leading-relaxed text-text-secondary">
      <div>
        Create a free key at{' '}
        <a
          href="https://auth.abuse.ch/"
          target="_blank"
          rel="noopener noreferrer"
          className="text-accent-green underline"
        >
          https://auth.abuse.ch/
        </a>
        , then paste it below.
      </div>
      <form onSubmit={handleSave} className="mt-1.5 flex gap-1.5">
        <input
          type="password"
          autoComplete="off"
          value={key}
          onChange={(e) => setKey(e.target.value)}
          placeholder="abuse.ch Auth-Key"
          aria-label="abuse.ch Auth-Key"
          className="min-w-0 flex-1 border border-border bg-bg px-2 py-1 text-[10px] text-text-primary outline-none focus:border-border-active"
        />
        <button
          type="submit"
          disabled={save.isPending || !key.trim()}
          className="border border-accent-green/40 bg-accent-green/10 px-2 py-1 text-[9px] tracking-wider text-accent-green hover:bg-accent-green/20 disabled:opacity-40"
        >
          {save.isPending ? '···' : 'SAVE KEY'}
        </button>
      </form>
      {save.isError && <div className="mt-1 text-accent-red">{save.error.message}</div>}

      <div className="mt-2 text-text-muted">
        Creating the key later? Import a URLhaus CSV you already have to use as a saved copy until then:{' '}
        <label className="cursor-pointer text-accent-green underline">
          choose CSV
          <input type="file" accept=".csv,.txt,text/csv,text/plain" onChange={handleFile} className="hidden" />
        </label>
      </div>
      {importCsv.isPending && <div className="mt-1 text-text-muted">Importing…</div>}
      {importCsv.isError && <div className="mt-1 text-accent-red">{importCsv.error.message}</div>}
    </div>
  )
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
                <StatusDot variant={info.error ? 'red' : info.refreshed_at ? 'green' : info.needs_key ? 'amber' : 'muted'} />
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
              {info.source && (
                <div className="text-[9px] text-text-muted">source: {SOURCE_LABELS[info.source] || info.source}</div>
              )}
              {info.error && <div className="mt-1 text-[9px] text-accent-red">{info.error}</div>}
              {name === 'urlhaus' && <UrlhausSetup info={info} />}
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
