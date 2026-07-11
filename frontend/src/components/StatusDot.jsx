const VARIANTS = {
  green: 'bg-accent-green shadow-[0_0_5px_var(--color-accent-green)]',
  amber: 'bg-accent-amber',
  red: 'bg-accent-red shadow-[0_0_5px_var(--color-accent-red)]',
  muted: 'bg-text-muted',
}

export function StatusDot({ variant = 'muted', pulse = false, className = '' }) {
  return (
    <span
      className={`inline-block h-[7px] w-[7px] flex-shrink-0 rounded-full ${VARIANTS[variant]} ${
        pulse ? 'animate-[pulse-live_2s_infinite]' : ''
      } ${className}`}
    />
  )
}
