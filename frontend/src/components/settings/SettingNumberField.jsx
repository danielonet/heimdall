import { useEffect, useState } from 'react'

/** A labeled number input + save button bound to one field of the
 * /api/settings PATCH body. Local edits are tracked separately from the
 * server value so typing doesn't fight the 15s refetch, and SAVE only
 * enables once the value is both valid and actually changed. */
export function SettingNumberField({ label, unit, value, min, max, pending, onSave }) {
  const [text, setText] = useState('')

  useEffect(() => {
    if (value != null) setText(String(value))
  }, [value])

  const parsed = Number(text)
  const isValid = text !== '' && Number.isInteger(parsed) && parsed >= min && parsed <= max
  const isDirty = value != null && String(value) !== text

  return (
    <div>
      <label className="mb-1 block text-[9px] tracking-wider text-text-muted">{label}</label>
      <div className="flex items-center gap-2">
        <input
          type="number"
          min={min}
          max={max}
          value={text}
          onChange={(e) => setText(e.target.value)}
          className="w-24 border border-border bg-bg px-3 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
        />
        {unit && <span className="text-[9px] text-text-muted">{unit}</span>}
        <button
          type="button"
          disabled={!isValid || !isDirty || pending}
          onClick={() => onSave(parsed)}
          className="border border-accent-green/30 bg-accent-green/5 px-3 py-1.5 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
        >
          {pending ? '···' : 'SAVE'}
        </button>
      </div>
      {text !== '' && !isValid && (
        <div className="mt-1 text-[9px] text-accent-red">
          Must be a whole number between {min} and {max}.
        </div>
      )}
    </div>
  )
}
