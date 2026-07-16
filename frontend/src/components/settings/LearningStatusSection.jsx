import { Badge } from '../Badge'
import { TimeAgo } from '../TimeAgo'
import { useHealth } from '../../hooks/useHealth'
import { useSettings, useUpdateSettings } from '../../hooks/useSettings'
import { SettingNumberField } from './SettingNumberField'

const MIN_HOURS = 1
const MAX_HOURS = 24 * 30 // 30 days — must match sentinel/api/routes/settings.py

export function LearningStatusSection() {
  const { data, isLoading } = useSettings()
  const { data: health } = useHealth()
  const mutation = useUpdateSettings()

  const security = health?.security_services

  return (
    <div className="border border-border bg-surface p-4">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="text-[8px] tracking-[3px] text-text-muted">ANOMALY DETECTION</div>
        {!isLoading && data && (
          <Badge variant={data.status === 'ARMED' ? 'success' : 'warning'}>{data.status}</Badge>
        )}
      </div>

      {isLoading && <div className="text-[10px] text-text-muted">Loading…</div>}

      {!isLoading && data && (
        <>
          <p className="mb-3 text-[10px] leading-relaxed text-text-secondary">
            {data.status === 'LEARNING' ? (
              <>
                The system is still building a traffic baseline — a device that hasn't been observed for a
                full learning period yet is exempt from ANOMALOUS_VOLUME alerts, since there's not enough
                history to tell normal from anomalous. This is expected right after a fresh install or a
                database purge, and clears automatically once the window below has elapsed.
              </>
            ) : (
              <>Baseline established{data.baseline_established_at && <> — armed since <TimeAgo iso={data.baseline_established_at} /></>}. ML anomaly detection is active for devices that have cleared the learning window.</>
            )}
          </p>

          {data.status === 'LEARNING' && (
            <div className="mb-3 border border-accent-amber/30 bg-accent-amber/5 p-2.5 text-[9px] leading-relaxed text-accent-amber">
              Other defenses stay fully active while learning — new-device detection, ARP spoofing watch,
              OpenCanary honeypot monitoring, and rule-based alerts are not affected.
              {security && (
                <div className="mt-1.5 flex flex-wrap gap-1.5">
                  <Badge variant={security.arp_watch_active ? 'success' : 'danger'}>
                    ARP WATCH {security.arp_watch_active ? 'ACTIVE' : 'OFFLINE'}
                  </Badge>
                  <Badge variant={security.fingerprint_active ? 'success' : 'danger'}>
                    FINGERPRINT {security.fingerprint_active ? 'ACTIVE' : 'OFFLINE'}
                  </Badge>
                  <Badge variant={security.canary_last_check_at ? 'success' : 'info'}>
                    CANARY {security.canary_last_check_at ? 'ACTIVE' : 'IDLE'}
                  </Badge>
                </div>
              )}
            </div>
          )}

          <SettingNumberField
            label="LEARNING PERIOD"
            unit="hours"
            value={data.ml_learning_period_hours}
            min={MIN_HOURS}
            max={MAX_HOURS}
            pending={mutation.isPending}
            onSave={(hours) => mutation.mutate({ ml_learning_period_hours: hours })}
          />
        </>
      )}

      {mutation.isError && <div className="mt-2 text-[9px] text-accent-red">{mutation.error.message}</div>}
    </div>
  )
}
