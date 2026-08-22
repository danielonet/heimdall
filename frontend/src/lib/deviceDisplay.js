// The name a user actually recognizes a device by — a user-set nickname
// beats the router-reported hostname, which beats the bare MAC. nickname is
// the durable label (see sentinel/db/models.py:Device.nickname — nothing in
// the poll loop ever touches it, unlike hostname, which the router can
// overwrite on any given poll).
export function deviceDisplayName(device) {
  return device.nickname || device.hostname || device.mac_address
}

// Mirrors sentinel/security/mac_vendor.py:is_locally_administered() — bit 1
// (the U/L bit) of the first octet. A blank vendor_name is ambiguous on its
// own (could be a real, just-unregistered OUI); this is what actually
// explains it as "this is a private/randomized address", not a lookup gap.
export function isLocallyAdministeredMac(mac) {
  if (!mac) return false
  const firstOctet = parseInt(mac.split(':')[0], 16)
  return Number.isFinite(firstOctet) && (firstOctet & 0b10) !== 0
}
