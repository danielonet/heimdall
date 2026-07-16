import { useEffect, useState } from 'react'
import { useSettings, useUpdateSettings } from '../../hooks/useSettings'

export function NtfyUrlSection() {
  const { data, isLoading } = useSettings()
  const mutation = useUpdateSettings()
  const [url, setUrl] = useState('')

  useEffect(() => {
    if (data) setUrl(data.ntfy_url || '')
  }, [data])

  const isDirty = data && url !== (data.ntfy_url || '')

  return (
    <div className="border border-border bg-surface p-4">
      <div className="mb-1 text-[8px] tracking-[3px] text-text-muted">PUSH — NTFY.SH</div>
      <p className="mb-3 text-[10px] leading-relaxed text-text-secondary">
        Push notifications for CRITICAL/WARNING alerts via{' '}
        <a href="https://ntfy.sh" target="_blank" rel="noreferrer" className="text-accent-blue underline">
          ntfy.sh
        </a>{' '}
        (self-hosted or the public instance). Leave blank to disable. Applies immediately, no restart needed.
      </p>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && (
        <div className="flex flex-wrap items-end gap-3">
          <div className="flex-1 min-w-[16rem]">
            <label htmlFor="ntfy-url" className="mb-1 block text-[9px] tracking-wider text-text-muted">
              TOPIC URL
            </label>
            <input
              id="ntfy-url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://ntfy.sh/heimdall-alerts"
              className="w-full border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
            />
          </div>
          <button
            type="button"
            disabled={!isDirty || mutation.isPending}
            onClick={() => mutation.mutate({ ntfy_url: url })}
            className="border border-accent-green/30 bg-accent-green/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
          >
            {mutation.isPending ? 'SAVING…' : 'SAVE'}
          </button>
        </div>
      )}

      {mutation.isError && <div className="mt-2 text-[9px] text-accent-red">{mutation.error.message}</div>}
    </div>
  )
}
