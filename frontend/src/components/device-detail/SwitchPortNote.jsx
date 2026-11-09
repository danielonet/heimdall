// A device a managed switch credits with a whole port: its traffic figures are the switch's counters for that port.
// See docs/router-and-switch-expansion-plan.md. Shown only while the switch has recently confirmed it.
export function SwitchPortNote({ switchName, switchPort }) {
  return (
    <div className="border border-accent-blue/30 bg-accent-blue/5 p-3 text-[10px] text-text-secondary">
      This device is the only one on port {switchPort} of {switchName}, so that port’s counters are this device’s own
      traffic. The figures count every byte the port carries (frame headers and broadcast traffic included), so they
      read slightly higher than the data the device itself sent or received.
    </div>
  )
}
