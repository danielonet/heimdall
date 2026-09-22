import { isLocallyAdministeredMac } from './deviceDisplay'

// Best-effort "what is this probably?" from an OUI vendor name — a guess
// from the manufacturer alone, never a fact (a Samsung MAC could be a
// phone, TV, or fridge). Ordered: first matching keyword wins, so more
// specific entries go first. Keywords are matched case-insensitively
// against the vendor_name. Extend freely.
const VENDOR_GUESSES = [
  [['apple'], 'Probably an iPhone, iPad or Mac'],
  [['samsung'], 'Probably a Samsung phone or TV'],
  [['xiaomi', 'redmi', 'beijing xiaomi'], 'Probably a Xiaomi phone or smart-home device'],
  [['huawei', 'honor'], 'Probably a Huawei phone'],
  [['oneplus', 'oppo', 'vivo', 'realme'], 'Probably a smartphone'],
  [['google'], 'Probably a Pixel phone or Nest device'],
  [['motorola', 'lenovo mobile'], 'Probably a smartphone'],
  [['sony'], 'Probably a phone, TV or PlayStation'],
  [['nintendo'], 'Probably a game console'],
  [['microsoft'], 'Probably a PC or Xbox'],
  [['intel', 'liteon', 'lite-on', 'azurewave', 'realtek', 'killer', 'qualcomm atheros'], 'Probably a laptop or PC'],
  [['hon hai', 'foxconn', 'cloud network technology', 'wistron', 'quanta', 'compal', 'pegatron'], 'Probably a laptop or PC'],
  [['dell', 'hewlett', 'hp inc', 'asustek', 'acer', 'lenovo', 'msi', 'micro-star'], 'Probably a laptop or PC'],
  [['amazon'], 'Probably an Echo, Fire TV or Kindle'],
  [['espressif', 'tuya', 'shenzhen'], 'Probably a smart-home / IoT gadget'],
  [['tp-link', 'tplink', 'netgear', 'asus', 'ubiquiti', 'mikrotik', 'zyxel', 'sagemcom', 'd-link', 'arris', 'technicolor'], 'Probably a router or access point'],
  [['hikvision', 'dahua', 'reolink', 'chuangmi', 'imilab', 'yi technology'], 'Probably an IP camera'],
  [['roku', 'lg electronics', 'tcl', 'hisense', 'vizio'], 'Probably a TV or streaming box'],
  [['sonos', 'bose', 'harman'], 'Probably a speaker'],
  [['canon', 'epson', 'brother', 'xerox'], 'Probably a printer'],
  [['raspberry'], 'Probably a Raspberry Pi'],
]

// A beacon always comes from an access point, so the type is never in
// doubt — the useful guess is *whose* and what kind of radio. A
// locally-administered BSSID is how routers label extra radios (guest
// networks, 5GHz, mesh nodes) derived from their main one.
export function guessNetworkDevice(vendorName, bssid) {
  const vendor = (vendorName || '').toLowerCase()
  const extra = isLocallyAdministeredMac(bssid) ? ' (extra radio: guest, 5GHz or mesh)' : ''
  if (vendor.includes('xiaomi') || vendor.includes('redmi')) return `Probably a Xiaomi/Redmi router${extra}`
  if (vendor.includes('tp-link') || vendor.includes('tplink')) return `Probably a TP-Link router${extra}`
  if (vendor.includes('sagemcom') || vendor.includes('arris') || vendor.includes('technicolor')) {
    return `Probably an ISP-supplied router${extra}`
  }
  if (vendor.includes('huawei') || vendor.includes('zte')) return `Probably a Huawei/ZTE router${extra}`
  if (vendor.includes('ubiquiti') || vendor.includes('mikrotik') || vendor.includes('netgear')) {
    return `Probably a router or access point${extra}`
  }
  if (vendor.includes('samsung') || vendor.includes('lg ') || vendor.includes('hp ') || vendor.includes('canon')) {
    return `Probably a phone hotspot, printer or TV${extra}`
  }
  return vendor ? `Probably a router or access point${extra}` : `Router or access point${extra}`
}

export function guessDeviceType(vendorName, mac) {
  const vendor = (vendorName || '').toLowerCase()
  if (vendor) {
    for (const [keywords, guess] of VENDOR_GUESSES) {
      if (keywords.some((k) => vendor.includes(k))) return guess
    }
    return 'Unknown vendor type'
  }
  // No vendor: a randomized (locally administered) MAC is what modern
  // phones/laptops use for WiFi privacy — see isLocallyAdministeredMac.
  if (isLocallyAdministeredMac(mac)) return 'Probably a phone or laptop (private address)'
  return 'Unknown'
}
