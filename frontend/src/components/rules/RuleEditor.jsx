import { useState } from 'react'
import { useMutation, useQueryClient } from '@tanstack/react-query'
import { apiJson } from '../../lib/api'

// Only the two triggers the real RuleEngine actually evaluates
// (sentinel/detection/rules_engine.py) — a "PORT_STATS" trigger would just
// silently never fire, so it isn't offered as an option here.
const TRIGGER_OPTIONS = ['TRAFFIC_SAMPLE', 'DEVICE_SNAPSHOT']

const FIELD_OPTIONS = {
  TRAFFIC_SAMPLE: ['throughput_up_kbps', 'throughput_dn_kbps', 'bytes_sent_delta', 'bytes_recv_delta', 'granularity'],
  DEVICE_SNAPSHOT: [
    'hostname',
    'ip_address',
    'vendor_name',
    'interface_name',
    'signal_strength_dbm',
    'signal_rate_mbps',
    'is_online',
  ],
}

const OPERATORS = ['GT', 'LT', 'GTE', 'LTE', 'EQ', 'NEQ', 'CONTAINS', 'IN']
const ACTION_TYPES = ['ALERT', 'BLOCK_DEVICE', 'NOTIFY', 'TAG_DEVICE', 'RATE_LIMIT']
const SEVERITIES = ['INFO', 'WARNING', 'CRITICAL']

function emptyForm() {
  return {
    name: '',
    trigger: 'TRAFFIC_SAMPLE',
    field: 'throughput_up_kbps',
    op: 'GT',
    value: '',
    window_polls: '1',
    actionType: 'ALERT',
    severity: 'WARNING',
    notify: false,
    tag: '',
    minutes: '30',
  }
}

function ruleToForm(rule) {
  const c = rule.condition_json || {}
  const a = rule.action_json || {}
  return {
    name: rule.name,
    trigger: c.trigger || 'TRAFFIC_SAMPLE',
    field: c.field || 'throughput_up_kbps',
    op: c.op || 'GT',
    value: c.value != null ? String(c.value) : '',
    window_polls: c.window_polls != null ? String(c.window_polls) : '1',
    actionType: a.type || 'ALERT',
    severity: a.severity || 'WARNING',
    notify: !!a.notify,
    tag: a.tag || '',
    minutes: a.minutes != null ? String(a.minutes) : '30',
  }
}

// Rule condition values are typed (numbers for GT/LT, strings for CONTAINS,
// arrays for IN) — the raw input is just text, so infer the shape from it.
function parseValue(raw) {
  if (raw === '') return ''
  if (raw.includes(',')) return raw.split(',').map((s) => s.trim())
  const num = Number(raw)
  return raw.trim() !== '' && !Number.isNaN(num) ? num : raw
}

function formToPayload(form) {
  const condition_json = { trigger: form.trigger, field: form.field, op: form.op, value: parseValue(form.value) }
  const windowPolls = parseInt(form.window_polls, 10)
  if (windowPolls > 1) condition_json.window_polls = windowPolls

  const action_json = { type: form.actionType }
  if (form.severity !== 'WARNING') action_json.severity = form.severity
  if (form.notify) action_json.notify = true
  if (form.actionType === 'TAG_DEVICE') action_json.tag = form.tag || 'flagged'
  if (form.actionType === 'RATE_LIMIT') action_json.minutes = parseInt(form.minutes, 10) || 30

  return { name: form.name, condition_json, action_json }
}

export function RuleEditor({ rule, onClose }) {
  const qc = useQueryClient()
  const [form, setForm] = useState(() => (rule ? ruleToForm(rule) : emptyForm()))
  const [testResult, setTestResult] = useState(null)

  const setField = (key) => (e) =>
    setForm((f) => ({ ...f, [key]: e.target.type === 'checkbox' ? e.target.checked : e.target.value }))

  const save = useMutation({
    mutationFn: () => {
      const payload = formToPayload(form)
      return rule
        ? apiJson(`/rules/${rule.id}`, { method: 'PUT', body: JSON.stringify(payload) })
        : apiJson('/rules', { method: 'POST', body: JSON.stringify({ ...payload, enabled: true }) })
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['rules'] })
      onClose()
    },
  })

  // Dry-run only exists for an already-persisted rule (POST /rules/:id/test),
  // and it evaluates whatever is currently saved in the DB — not unsaved
  // edits in this form. Save first if you want to test your latest changes.
  const test = useMutation({
    mutationFn: () => apiJson(`/rules/${rule.id}/test`, { method: 'POST' }),
    onSuccess: (result) => setTestResult(result),
  })

  return (
    <div className="mb-4 border border-accent-green/30 bg-surface p-4">
      <div className="mb-3 text-[8px] tracking-[3px] text-text-muted">{rule ? 'EDIT RULE' : 'NEW RULE'}</div>

      <label className="mb-1 block text-[9px] tracking-wider text-text-secondary">NAME</label>
      <input
        value={form.name}
        onChange={setField('name')}
        className="mb-3 w-full border border-border bg-bg px-2 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
      />

      <div className="mb-3 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div>
          <label className="mb-1 block text-[9px] tracking-wider text-text-secondary">TRIGGER</label>
          <select
            value={form.trigger}
            onChange={(e) => setForm((f) => ({ ...f, trigger: e.target.value, field: FIELD_OPTIONS[e.target.value][0] }))}
            className="w-full border border-border bg-bg px-2 py-1.5 text-[11px] text-text-primary outline-none"
          >
            {TRIGGER_OPTIONS.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-[9px] tracking-wider text-text-secondary">FIELD</label>
          <select
            value={form.field}
            onChange={setField('field')}
            className="w-full border border-border bg-bg px-2 py-1.5 text-[11px] text-text-primary outline-none"
          >
            {FIELD_OPTIONS[form.trigger].map((f) => (
              <option key={f} value={f}>
                {f}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-[9px] tracking-wider text-text-secondary">OPERATOR</label>
          <select
            value={form.op}
            onChange={setField('op')}
            className="w-full border border-border bg-bg px-2 py-1.5 text-[11px] text-text-primary outline-none"
          >
            {OPERATORS.map((op) => (
              <option key={op} value={op}>
                {op}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-[9px] tracking-wider text-text-secondary">VALUE</label>
          <input
            value={form.value}
            onChange={setField('value')}
            placeholder="5120 or a,b,c"
            className="w-full border border-border bg-bg px-2 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
          />
        </div>
      </div>

      <div className="mb-3">
        <label className="mb-1 block text-[9px] tracking-wider text-text-secondary">
          SUSTAINED FOR (CONSECUTIVE POLLS)
        </label>
        <input
          type="number"
          min="1"
          value={form.window_polls}
          onChange={setField('window_polls')}
          className="w-24 border border-border bg-bg px-2 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
        />
      </div>

      <div className="mb-3 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <div>
          <label className="mb-1 block text-[9px] tracking-wider text-text-secondary">ACTION</label>
          <select
            value={form.actionType}
            onChange={setField('actionType')}
            className="w-full border border-border bg-bg px-2 py-1.5 text-[11px] text-text-primary outline-none"
          >
            {ACTION_TYPES.map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-[9px] tracking-wider text-text-secondary">SEVERITY</label>
          <select
            value={form.severity}
            onChange={setField('severity')}
            className="w-full border border-border bg-bg px-2 py-1.5 text-[11px] text-text-primary outline-none"
          >
            {SEVERITIES.map((s) => (
              <option key={s} value={s}>
                {s}
              </option>
            ))}
          </select>
        </div>
        {form.actionType === 'TAG_DEVICE' && (
          <div>
            <label className="mb-1 block text-[9px] tracking-wider text-text-secondary">TAG</label>
            <input
              value={form.tag}
              onChange={setField('tag')}
              placeholder="flagged"
              className="w-full border border-border bg-bg px-2 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
            />
          </div>
        )}
        {form.actionType === 'RATE_LIMIT' && (
          <div>
            <label className="mb-1 block text-[9px] tracking-wider text-text-secondary">QUIET MINUTES</label>
            <input
              type="number"
              min="1"
              value={form.minutes}
              onChange={setField('minutes')}
              className="w-full border border-border bg-bg px-2 py-1.5 text-[11px] text-text-primary outline-none focus:border-border-active"
            />
          </div>
        )}
        <label className="flex items-end gap-2 pb-1.5 text-[10px] text-text-secondary">
          <input type="checkbox" checked={form.notify} onChange={setField('notify')} />
          Also send a push/email notification
        </label>
      </div>

      {save.isError && <div className="mb-3 text-[10px] text-accent-red">{save.error.message}</div>}

      <div className="flex flex-wrap items-center gap-2">
        <button
          type="button"
          disabled={save.isPending || !form.name.trim()}
          onClick={() => save.mutate()}
          className="border border-accent-green/40 bg-accent-green/10 px-4 py-2 text-[10px] tracking-wider text-accent-green transition-colors hover:bg-accent-green/20 disabled:opacity-40"
        >
          {save.isPending ? 'SAVING…' : rule ? 'SAVE CHANGES' : 'CREATE RULE'}
        </button>
        <button
          type="button"
          onClick={onClose}
          className="border border-border px-4 py-2 text-[10px] tracking-wider text-text-muted"
        >
          CANCEL
        </button>
        {rule && (
          <button
            type="button"
            disabled={test.isPending}
            onClick={() => test.mutate()}
            className="border border-accent-blue/40 bg-accent-blue/10 px-4 py-2 text-[10px] tracking-wider text-accent-blue transition-colors hover:bg-accent-blue/20 disabled:opacity-40"
          >
            {test.isPending ? 'TESTING…' : 'TEST (SAVED VERSION)'}
          </button>
        )}
        {!rule && (
          <span className="text-[9px] text-text-muted">Save the rule first to dry-run test it.</span>
        )}
      </div>

      {testResult && (
        <div className="mt-3 border border-border bg-bg p-3 text-[10px]">
          <div className="mb-2 text-text-secondary">
            Evaluated {testResult.evaluated} {testResult.trigger === 'DEVICE_SNAPSHOT' ? 'devices' : 'samples'} —{' '}
            <span className="text-accent-green">{testResult.matched} matched</span>
          </div>
          {testResult.matches.length > 0 && (
            <ul className="space-y-1 text-text-muted">
              {testResult.matches.map((m, i) => (
                <li key={i}>
                  {m.mac_address} → {JSON.stringify(m.actual_value)}
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  )
}
