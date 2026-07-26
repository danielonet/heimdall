import { Modal } from './Modal'

// A wholly fictional crew, styled as Nordic saga heroes — Heimdall's own
// watchmen. None of these are real people; it's an easter egg (Ctrl+Shift +
// double-click the logo), not an attribution record.
const CREW = [
  { name: 'Ragnar Packetbane', role: 'Lead Backend Architect', quote: 'A shield wall is only as strong as its weakest packet.' },
  { name: 'Astrid Nullshield', role: 'Principal ML Engineer', quote: 'Every anomaly tells a saga; I just read the runes.' },
  { name: 'Björn Ironrouter', role: 'DevOps & Infrastructure Chieftain', quote: 'The fleet sails on Docker Compose, or it does not sail at all.' },
  { name: 'Freydis Firewallsdóttir', role: 'Security Research Lead', quote: 'I have seen the exploit, and the exploit is not enough.' },
  { name: 'Leif Tracewalker', role: 'Frontend Lead', quote: 'A dashboard unseen is a battle unfought.' },
  { name: 'Skadi Coldtrace', role: 'Detection Engineering Lead', quote: 'I hunt in the frost of false positives.' },
  { name: 'Gunnar Threadsplitter', role: 'Async & Concurrency Engineer', quote: 'One event loop to rule them all.' },
  { name: 'Solveig Logrunes', role: 'Database & Schema Architect', quote: 'Every hypertable holds a thousand winters of data.' },
  { name: 'Halvor Honeypot', role: 'Threat Intelligence Analyst', quote: 'Bait the wolf, and the wolf reveals itself.' },
  { name: 'Ylva Nightwatch', role: 'QA & Release Engineer', quote: 'Trust, but regression-test.' },
  { name: 'Vidar Blockhand', role: 'Product Manager', quote: 'Ship the shield wall before the raid, not after.' },
  { name: 'Eira Signalveil', role: 'UX / UI Designer', quote: 'Beauty is a dashboard that never lies.' },
  { name: 'Torbjørn Deepscan', role: 'Network Scanning Specialist', quote: 'Every port is a door; I knock first.' },
  { name: 'Saga Chronicles', role: 'Documentation & Project Manager', quote: 'What is not written was never truly built.' },
  { name: 'Njord Beaconwatch', role: 'C2 & Beaconing Detection Specialist', quote: 'Regularity is the tell of the machine, not the man.' },
]

export function CreditsModal({ onClose }) {
  return (
    <Modal title="THE WATCHMEN OF HEIMDALL" size="lg" onClose={onClose}>
      <div className="mb-4 text-[10px] leading-relaxed text-text-secondary">
        Every shield wall has its warriors. None of them are real — but the
        code they left behind is.
      </div>
      <div className="grid max-h-[60vh] grid-cols-1 gap-3 overflow-y-auto pr-1 sm:grid-cols-2">
        {CREW.map((member) => (
          <div key={member.name} className="border border-border bg-surface p-3">
            <div className="font-heading text-[12px] font-semibold tracking-wide text-accent-green">
              {member.name}
            </div>
            <div className="mt-0.5 text-[9px] tracking-[1.5px] text-accent-blue">
              {member.role.toUpperCase()}
            </div>
            <div className="mt-2 text-[10px] italic leading-relaxed text-text-secondary">
              &ldquo;{member.quote}&rdquo;
            </div>
          </div>
        ))}
      </div>
      <div className="mt-4 text-right text-[8px] tracking-[2px] text-text-muted">
        HEIMDALL WATCHES · SO YOU DON&apos;T HAVE TO
      </div>
    </Modal>
  )
}
