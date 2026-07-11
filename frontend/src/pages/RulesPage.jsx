import { useState } from 'react'
import { useRules } from '../hooks/useRules'
import { RuleRow } from '../components/rules/RuleRow'
import { RuleEditor } from '../components/rules/RuleEditor'

export function RulesPage() {
  const { data: rules, isLoading } = useRules()
  const [editing, setEditing] = useState(null) // null closed, 'new', or a rule object

  return (
    <div className="p-4">
      <div className="mb-4 flex items-center justify-between">
        <div className="text-[8px] tracking-[3px] text-text-muted">DETECTION RULES</div>
        {editing === null && (
          <button
            type="button"
            onClick={() => setEditing('new')}
            className="border border-accent-green/40 bg-accent-green/10 px-3 py-1.5 text-[10px] tracking-wider text-accent-green hover:bg-accent-green/20"
          >
            + NEW RULE
          </button>
        )}
      </div>

      {editing !== null && (
        <RuleEditor rule={editing === 'new' ? null : editing} onClose={() => setEditing(null)} />
      )}

      <div className="border border-border bg-surface">
        {isLoading && <div className="p-4 text-center text-[10px] text-text-muted">Loading…</div>}
        {!isLoading && (!rules || rules.length === 0) && (
          <div className="p-4 text-center text-[10px] text-text-muted">
            No rules yet — create one to act on alerts automatically.
          </div>
        )}
        {(rules || []).map((rule) => (
          <RuleRow key={rule.id} rule={rule} onEdit={setEditing} />
        ))}
      </div>
    </div>
  )
}
