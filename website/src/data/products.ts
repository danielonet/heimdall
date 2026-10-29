// One entry per security product page (/security/<slug>/). Every entry fills the same six blocks.
// Facts come from README.md "Defenses & Capabilities" and docs/architecture/04-detection-pipeline.md
// (alert registry), checked against a running stack.
export type Tier = 'minimal' | 'intermediate' | 'full';

export interface Product {
  slug: string;
  name: string;
  group: 'Sensors' | 'Analysis' | 'Intelligence' | 'Response';
  kind: string;
  what: string;
  sees: string;
  catches: { alert: string; severity: string; meaning: string }[];
  plugs: string[];
  tier: Tier;
  tierNote: string;
  limits: string[];
  related: string[];
}

export const products: Product[] = [
  {
    slug: 'router-adapter', name: 'Router adapter', group: 'Sensors', kind: 'Inventory and actuator',
    what: 'The one place Heimdall talks to your router. It reads the device list and traffic counters, and carries out block and quarantine.',
    sees: 'Whatever your router’s own interface exposes: connected devices, WiFi signal and access point, port and WAN counters. Which of these you get depends on the router (see the equipment table).',
    catches: [
      { alert: 'NEW_DEVICE', severity: 'CRITICAL', meaning: 'A device joined that has not been seen before.' },
      { alert: 'HIGH_UPLOAD', severity: 'WARNING', meaning: 'A sustained upload-heavy pattern, with thresholds per device type (a NAS or camera is expected to upload more than a phone).' },
      { alert: 'SIGNAL_ANOMALY', severity: 'WARNING', meaning: 'A WiFi device’s signal shifts and holds at a new level, a possible sign of a cloned device.' },
      { alert: 'AP_TRUST_CROSSING', severity: 'WARNING / CRITICAL', meaning: 'A device moves between the guest and private WiFi; critical if it gains private access it did not have.' },
      { alert: 'WAN_BANDWIDTH_SPIKE', severity: 'WARNING', meaning: 'Household internet traffic spikes.' },
      { alert: 'DEVICE_IDENTITY_LINKED', severity: 'INFO', meaning: 'A device that rejoined under a new randomised MAC address was recognised as one you already had, and the two records were linked.' },
    ],
    plugs: ['Router', 'Adapter', 'Detectors', 'Alert store', 'Correlation', 'Block / Quarantine'],
    tier: 'minimal', tierNote: 'Part of the core stack. With an unsupported router, passive mode builds the device list from the ARP table instead.',
    limits: [
      'Wired devices are measured per router port, not per device. Heimdall labels these PORT TOTAL and never shows them as per-device traffic.',
      'Block and quarantine only work on routers whose adapter supports them.',
      'Only the Sagemcom and Xiaomi/Redmi adapters have been run against real hardware.',
    ],
    related: ['detectors', 'ml-engine', 'response'],
  },
  {
    slug: 'detectors', name: 'Passive detectors', group: 'Sensors', kind: 'Packet sniffing',
    what: 'Watchers that listen on your network and never send anything, so the device being watched cannot tell.',
    sees: 'Packets on the interface Heimdall sniffs (set on the Settings tab), plus the router’s polled state.',
    catches: [
      { alert: 'ARP_SPOOF', severity: 'CRITICAL', meaning: 'A known IP suddenly answers from a different MAC address, the signature of a man-in-the-middle attack.' },
      { alert: 'ROGUE_DHCP_SERVER', severity: 'CRITICAL', meaning: 'A DHCP offer came from something that is not your router.' },
      { alert: 'FINGERPRINT_MISMATCH', severity: 'CRITICAL', meaning: 'A known device’s passively guessed operating system suddenly changes.' },
      { alert: 'VENDOR_MISMATCH', severity: 'WARNING', meaning: 'A hostname implies a different hardware vendor than the device’s MAC address.' },
      { alert: 'VENDOR_UNVERIFIED', severity: 'INFO', meaning: 'A hostname implies a vendor but none could be looked up for the MAC address. Often a phone using a randomised address, so worth a glance rather than an alarm.' },
      { alert: 'IP_CONFLICT', severity: 'INFO', meaning: 'Two addresses clash for a device you have marked as trusted.' },
    ],
    plugs: ['Scapy sniffer', 'ARP / DHCP / fingerprint watcher', 'Alert store', 'Correlation', 'Auto-block (optional)'],
    tier: 'minimal', tierNote: 'Part of the core stack, in every tier.',
    limits: [
      'They see only traffic that reaches the sniff interface; a wired port is strongly preferred.',
      'In passive-router mode there is no DHCP server to ask, so a normal address reassignment can raise a false ARP_SPOOF alert.',
      'On an ordinary switch the sniff interface hears broadcast and multicast traffic and the Heimdall machine’s own, not other devices’ private conversations. In a 25-second test on a wired home port, none of the traffic seen was between two other devices.',
    ],
    related: ['router-adapter', 'response', 'suricata'],
  },
  {
    slug: 'wifi-monitor', name: 'WiFi monitor', group: 'Sensors', kind: 'Radio listening',
    what: 'Listens to WiFi over the air with a second, dedicated adapter, to spot an access point pretending to be yours and to list nearby devices and networks.',
    sees: 'The beacon and probe frames that every nearby access point and phone broadcasts, on 2.4 GHz channels 1, 6 and 11. It never joins any network.',
    catches: [
      { alert: 'ROGUE_AP', severity: 'CRITICAL', meaning: 'Something that is not one of your access points is broadcasting a network name you listed as protected: the signature of an “evil twin” attack.' },
    ],
    plugs: ['Monitor-mode WiFi adapter', 'Beacon and probe frames', 'WiFi monitor', 'ROGUE_AP', 'Alert store', 'Correlation'],
    tier: 'minimal', tierNote: 'Runs inside the core backend in every tier, but stays off until you add a second WiFi adapter that supports monitor mode and choose it under WiFi monitor on the Equipment page.',
    limits: [
      'It needs extra hardware: a USB WiFi adapter that supports monitor mode, separate from the one that connects the Heimdall machine to your network.',
      'It listens on 2.4 GHz channels 1, 6 and 11 only, so an access point on 5 GHz or another channel can be missed.',
      'You must list your own access points’ real addresses (BSSIDs) next to the protected names; “Detect from my router” in Settings suggests them, but you confirm them. A protected name with one of your own access points left out raises a false alarm.',
      'It cannot block a rogue access point, because it is not a device on your network. The alert tells you; the response is physical.',
      'The nearby-device and network lists on the WiFi page are for your information only and do not raise alerts.',
    ],
    related: ['detectors', 'router-adapter', 'response'],
  },
  {
    slug: 'ml-engine', name: 'Anomaly engine (ML)', group: 'Analysis', kind: 'Per-device machine learning',
    what: 'A separate model for every device, trained on that device’s own history, that flags traffic volume which is unusual for it.',
    sees: 'The per-device traffic samples the router adapter collects. A device is only judged against its own past, never against other devices.',
    catches: [
      { alert: 'ANOMALOUS_VOLUME', severity: 'WARNING', meaning: 'Traffic volume is a statistical outlier for this device, according to an IsolationForest and a Local Outlier Factor model.' },
    ],
    plugs: ['Traffic samples', 'Per-device IsolationForest + LOF', 'ANOMALOUS_VOLUME', 'Alert store'],
    tier: 'minimal', tierNote: 'Part of the core stack. Needs a router adapter that reports per-device traffic.',
    limits: [
      'Needs history before it is useful; a new device has nothing to compare against yet.',
      'Does nothing in passive-router mode: with no per-device traffic, nothing is estimated or invented.',
      'Wired devices on routers that only count per port are not modelled as if measured per device.',
    ],
    related: ['router-adapter', 'detectors'],
  },
  {
    slug: 'nmap', name: 'Nmap', group: 'Analysis', kind: 'Active scanning',
    what: 'A nightly scan of every device Heimdall already knows, looking for open doors and weak defaults.',
    sees: 'Services, operating system and vulnerabilities, found by actively probing known devices from the Heimdall host.',
    catches: [
      { alert: 'HIGH_RISK_PORT_OPENED', severity: 'CRITICAL', meaning: 'A newly opened high-risk port such as Telnet, SMB, RDP or VNC.' },
      { alert: 'VULNERABILITY_DETECTED', severity: 'CRITICAL', meaning: 'A known vulnerability found by Nmap’s vulnerability scripts.' },
      { alert: 'CREDENTIAL_EXPOSURE_DETECTED', severity: 'CRITICAL', meaning: 'A default, blank or anonymous login works on a service.' },
      { alert: 'OS_FINGERPRINT_CONFLICT', severity: 'WARNING', meaning: 'The scan’s operating-system guess disagrees with the passive one on file.' },
    ],
    plugs: ['Scheduler (nightly)', 'Nmap', 'Findings', 'Alert store', 'Correlation'],
    tier: 'minimal', tierNote: 'Part of the core stack, in every tier.',
    limits: [
      'It scans outward, against devices Heimdall already knows. It does not detect someone scanning you.',
      'An active scan is visible to the devices it probes and may trip their own logging.',
    ],
    related: ['detectors', 'threat-intel', 'response'],
  },
  {
    slug: 'zeek', name: 'Zeek', group: 'Analysis', kind: 'Traffic inspection',
    what: 'A network analyser that writes a log of every DNS lookup and connection, so Heimdall can spot patterns no single packet shows.',
    sees: 'Cleartext DNS queries, connection timing and downloaded files on the sniff interface.',
    catches: [
      { alert: 'DNS_MALICIOUS_QUERY', severity: 'CRITICAL', meaning: 'A device looked up a domain on the URLhaus malware feed.' },
      { alert: 'C2_BEACONING', severity: 'CRITICAL', meaning: 'A device connects to the same remote host at suspiciously regular intervals, a classic command-and-control beacon.' },
      { alert: 'MALICIOUS_TRAFFIC_DESTINATION', severity: 'CRITICAL', meaning: 'A traffic spike was sent to an address on a threat feed.' },
    ],
    plugs: ['Zeek container', 'dns.log / conn.log', 'Heimdall parser', 'Threat-intel lookup', 'Alert store', 'Correlation'],
    tier: 'full', tierNote: 'Full tier only. Needs about 4 GB of RAM across the full stack.',
    limits: [
      'DNS over HTTPS or TLS bypasses it: only cleartext DNS on port 53 is inspected.',
      'It sees only what reaches the sniff interface. On an ordinary switch that is the Heimdall machine’s own traffic plus broadcast and multicast, so to inspect other devices’ traffic the switch or router must mirror it to Heimdall’s port.',
    ],
    related: ['clamav', 'threat-intel', 'suricata'],
  },
  {
    slug: 'clamav', name: 'ClamAV', group: 'Analysis', kind: 'Malware scanning',
    what: 'An antivirus engine that scans files Zeek pulls out of your network’s downloads.',
    sees: 'Files extracted by Zeek from cleartext downloads.',
    catches: [{ alert: 'MALWARE_DETECTED', severity: 'CRITICAL', meaning: 'An extracted file matched a ClamAV signature.' }],
    plugs: ['Zeek file extraction', 'ClamAV', 'MALWARE_DETECTED', 'Alert store', 'Correlation'],
    tier: 'full', tierNote: 'Full tier only, together with Zeek.',
    limits: [
      'TLS-encrypted downloads bypass it: no TLS interception is configured, so those files are never extracted.',
      'It only knows the signatures it ships with.',
    ],
    related: ['zeek', 'threat-intel'],
  },
  {
    slug: 'suricata', name: 'Suricata', group: 'Analysis', kind: 'Network IDS',
    what: 'A signature-based intrusion detector. It compares live traffic against a rule set of known-bad patterns and tells Heimdall when one matches.',
    sees: 'Packets on the sniff interface. It writes each match as a line of JSON (its EVE log), which Heimdall reads.',
    catches: [{ alert: 'IDS_SIGNATURE_MATCH', severity: 'from the rule', meaning: 'A rule matched. Heimdall maps the rule’s own priority to a severity; the alert carries the rule name and devices involved.' }],
    plugs: ['Suricata container', 'EVE JSON log', 'suricata_parser', 'IDS_SIGNATURE_MATCH', 'Alert store', 'Correlation'],
    tier: 'full', tierNote: 'Full tier only. The container needs host networking and raw-socket capability, like Heimdall’s own sniffer.',
    limits: [
      'The rule set is not managed by Heimdall: it ingests whatever alerts the container produces and does not fetch, verify or tune rules.',
      'Expect noise at first: the stock Emerging Threats Open set is tuned for enterprise and ISP traffic, so ordinary home traffic can trigger alerts until you add suppressions.',
      'It cannot read encrypted payloads; no TLS interception is configured.',
      'It only inspects what reaches the sniff interface. On an ordinary switch that is the Heimdall machine’s own traffic plus broadcast and multicast, so to inspect other devices’ traffic the switch or router must mirror it to Heimdall’s port.',
    ],
    related: ['zeek', 'detectors', 'response'],
  },
  {
    slug: 'opencanary', name: 'OpenCanary', group: 'Analysis', kind: 'Honeypot',
    what: 'Decoy services that look vulnerable. Nothing legitimate ever uses them, so any contact at all is suspicious.',
    sees: 'Connection attempts to fake FTP (port 21), Telnet (2323), SSH (2222) and HTTP (8880) services on the Heimdall machine.',
    catches: [{ alert: 'HONEYPOT_ACCESS', severity: 'CRITICAL', meaning: 'Something touched a decoy service. The alert names the source address.' }],
    plugs: ['OpenCanary container', 'Decoy touched', 'HONEYPOT_ACCESS', 'Alert store', 'Correlation'],
    tier: 'intermediate', tierNote: 'Intermediate and full tiers.',
    limits: [
      'It only catches an attacker who actually touches a decoy.',
      'A decoy is a real listening service on the Heimdall host, so keep ports 3000 and 5000 off the internet and never forward decoy ports.',
      'The decoys use port 21 as is, so an FTP server already on the Heimdall machine would clash with it. Telnet and SSH sit on 2323 and 2222, leaving the real ports 23 and 22 alone.',
    ],
    related: ['detectors', 'response'],
  },
  {
    slug: 'threat-intel', name: 'Threat intelligence', group: 'Intelligence', kind: 'Reputation feeds',
    what: 'Public lists of known-bad addresses and domains that other detectors check against, refreshed nightly.',
    sees: 'Addresses and domains from Zeek, traffic spikes and your own lookups, compared with the feeds.',
    catches: [
      { alert: 'DNS_MALICIOUS_QUERY', severity: 'CRITICAL', meaning: 'Raised together with Zeek when a looked-up domain is on the URLhaus feed.' },
      { alert: 'MALICIOUS_TRAFFIC_DESTINATION', severity: 'CRITICAL', meaning: 'Raised together with Zeek when a traffic spike goes to a listed address.' },
    ],
    plugs: ['Feeds (nightly)', 'Reputation store', 'Zeek / spike enrichment', 'Alert store'],
    tier: 'minimal', tierNote: 'Feeds are part of the core stack; the Zeek checks need the full tier.',
    limits: [
      'The URLhaus feed needs a free abuse.ch key that you paste into the Threats tab. You can import a URLhaus CSV until then.',
      'On-demand lookups check the local blocklists with no setup. An optional AlienVault OTX key adds OTX report counts, and then the address you look up is sent to OTX.',
      'Reputation lists lag behind new threats.',
    ],
    related: ['zeek', 'clamav', 'nmap'],
  },
  {
    slug: 'response', name: 'Response and notification', group: 'Response', kind: 'Block, quarantine, notify',
    what: 'What happens after an alert: you act on it, or Heimdall does, and you hear about it where you already look.',
    sees: 'Every alert in the store. Correlation first recognises related pairs on one device, such as a brand-new device that immediately spoofs, and raises one higher-severity incident instead of two rows.',
    catches: [
      { alert: 'COMPROMISE_CHAIN_DETECTED', severity: 'CRITICAL', meaning: 'Two related alerts on one device within a short window, escalated into a single incident.' },
      { alert: 'RULE_TRIGGERED', severity: 'you choose (default WARNING)', meaning: 'One of the rules you wrote on the Rules page fired.' },
      { alert: 'AUTO_BLOCK_EXPIRED', severity: 'INFO', meaning: 'A timed automatic block ended and the device was unblocked.' },
      { alert: 'BLOCK_ENFORCEMENT_DRIFT', severity: 'WARNING / INFO', meaning: 'The router’s block state no longer matches Heimdall’s record.' },
    ],
    plugs: ['Alert store', 'Correlation', 'Block · Quarantine · Auto-block', 'Dashboard (WebSocket)', 'ntfy · Telegram · email · daily digest · CSV · /api/metrics'],
    tier: 'minimal', tierNote: 'Every tier. Block and quarantine need a router adapter that supports them.',
    limits: [
      'Auto-block is one global switch for all eligible alert types. It is on by default for a new install and can be turned off in Settings. An automatic block expires after 24 hours by default.',
      'In passive-router mode and on several adapters, Heimdall cannot block: use the router’s own admin page.',
      'Quarantine (cut internet, keep LAN) needs a router firewall rule; not every adapter has one.',
    ],
    related: ['router-adapter', 'detectors', 'suricata'],
  },
];

export const groups = ['Sensors', 'Analysis', 'Intelligence', 'Response'] as const;
export const bySlug = (s: string): Product | undefined => products.find((p) => p.slug === s);
