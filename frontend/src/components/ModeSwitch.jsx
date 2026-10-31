import { useSettings, useUpdateSettings } from '../hooks/useSettings'

// The two operating modes are one setting, auto_block_on_threat (also on the
// Settings page as AUTO-BLOCK ON THREAT): NOC only watches and alerts, SOC
// also blocks the offending device the moment a detector sees an attack.
// Full class names, not built from a colour variable: Tailwind only keeps classes it can read in the source.
const MODES = [
  ['noc', 'NOC', 'Watch only: threats raise alerts, nothing is blocked automatically',
    'border-accent-green/40 bg-accent-green/10 text-accent-green'],
  ['soc', 'SOC', 'Respond: ARP Watch, Passive Fingerprint and Nmap Scanner block the offending device automatically',
    'border-accent-red/40 bg-accent-red/10 text-accent-red'],
]

export function ModeSwitch({ compact = false }) {
  const { data } = useSettings()
  const mutation = useUpdateSettings()
  if (!data) return null

  const current = data.auto_block_on_threat ? 'soc' : 'noc'

  function choose(mode) {
    if (mode === current || mutation.isPending) return
    if (
      mode === 'soc' &&
      !window.confirm(
        'Switch to SOC mode? Heimdall will block a device from the network as soon as a detector flags an attack from it.',
      )
    ) {
      return
    }
    mutation.mutate({ auto_block_on_threat: mode === 'soc' })
  }

  return (
    <div className="flex items-center gap-2">
      <div role="group" aria-label="Operating mode" className="flex items-center">
        {MODES.map(([value, label, title, activeClass]) => {
          const active = current === value
          return (
            <button
              key={value}
              type="button"
              title={title}
              aria-pressed={active}
              disabled={mutation.isPending}
              onClick={() => choose(value)}
              className={`border px-2 py-1 text-[9px] tracking-wider transition-colors disabled:opacity-50 ${
                active ? activeClass : 'border-border text-text-muted hover:text-text-secondary'
              } ${value === 'noc' ? 'border-r-0' : ''}`}
            >
              {label}
            </button>
          )
        })}
      </div>
      {!compact && (
        <span className="whitespace-nowrap text-[9px] tracking-wide text-text-muted">
          {current === 'soc' ? 'RESPONDING' : 'WATCHING'}
        </span>
      )}
    </div>
  )
}
