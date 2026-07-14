// Flags a device the router has only ever seen listed (a DHCP reservation,
// a probe, etc.) but that has never actually joined the network — see
// devices.ever_connected / NewDeviceDetector. Distinct from is_online: a
// device can be ever_connected=true and currently offline (was here before,
// just not right now); this icon is only for devices that were never
// really here at all.
export function NeverConnectedIcon() {
  return (
    <span
      title="Never connected — the router has only ever listed this device, it has not actually joined the network"
      className="inline-flex h-3.5 w-3.5 flex-shrink-0 items-center justify-center rounded-full border border-accent-amber/50 text-[9px] leading-none text-accent-amber"
    >
      ◌
    </span>
  )
}
