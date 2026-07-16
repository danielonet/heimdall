import { useEffect } from 'react'
import { createPortal } from 'react-dom'

/** Generic overlay dialog matching the app's bordered/tracking-wide visual
 * language — for confirmations that need more weight than an inline form
 * (e.g. destructive actions). Closes on Escape or backdrop click, both of
 * which call onClose; the caller decides what that means (usually just
 * hiding the modal, not cancelling any in-flight action). */
export function Modal({ title, tone = 'default', onClose, children }) {
  useEffect(() => {
    function handleKeyDown(e) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', handleKeyDown)
    return () => document.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  const titleColor = tone === 'danger' ? 'text-accent-red' : 'text-accent-green'
  const borderColor = tone === 'danger' ? 'border-accent-red/40' : 'border-border-active'

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 p-4"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
        className={`w-full max-w-md border ${borderColor} bg-surface-elevated p-5 shadow-[0_0_40px_rgba(0,0,0,0.5)]`}
      >
        {title && (
          <div className={`mb-4 text-[9px] tracking-[3px] ${titleColor}`}>{title}</div>
        )}
        {children}
      </div>
    </div>,
    document.body,
  )
}
