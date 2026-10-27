# Passive adapter (`passive`)

For a router Heimdall has no adapter for. There is no router login: Heimdall
builds its device inventory from the monitoring host's own view of the LAN.
Select **Other / not listed (passive mode)** on the Equipment tab, then make it
the **Primary router**.

Code: `sentinel/adapter/passive/passive_adapter.py`. Tests:
`tests/test_adapter/test_passive_adapter.py`.

## How the inventory is built

| Source | Cost | What it gives |
|---|---|---|
| Kernel neighbour table (`ip -4 neigh show`), read every poll | none | Every device this host has exchanged traffic with: MAC, IP |
| ARP ping sweep (`nmap -sn -PR`) of the LAN subnet, every `PASSIVE_SWEEP_INTERVAL_S` (default 300 s, `0` = never) | a few seconds, one ARP request per address | Devices the host has not talked to yet, hostname (reverse DNS), vendor (when nmap runs as root, as in the container) |

The LAN subnet comes from the sniff interface (Settings → `sniff_iface`, or the
default route if blank). Only that interface's entries are used, because on a
host with Docker the neighbour table also lists bridge networks. A subnet wider
than /22 is never swept.

**Online / offline.** A device is online if it was confirmed within
`max(3 × sweep interval, 15 min)`. Confirmed means: it answered a sweep, or the
kernel lists it `REACHABLE`/`DELAY`/`PROBE`. A `STALE` entry alone proves the
device existed, not that it is still here, so while sweeps are on it only adds the
device to the inventory. With sweeps off, the neighbour table is the only
signal and `STALE` counts.

## What works, what does not

| | Passive mode |
|---|---|
| Device inventory, new-device alerts, online/offline, vendor lookup | Yes |
| ARP watch, rogue-DHCP watch, passive OS fingerprint, Nmap, Suricata, Zeek, ClamAV, OpenCanary, threat intel, notifications | Yes. These use the sniff interface or other hosts directly, not the router |
| Per-device traffic, traffic ML, upload-ratio detection | **No.** `get_traffic_samples()` returns `[]`; nothing is estimated (CLAUDE.md rule 5) |
| WAN throughput and WAN status, router model/firmware, ports, WiFi radios, AP / signal | **No.** WAN status is `UNKNOWN` |
| Block / quarantine | **No.** Both return `False`; use the router's own admin UI |
| Wired vs WiFi, which AP | Unknown (`interface_name` is blank) |

## ARP-spoof alerts without DHCP leases

When ARP Watch sees an IP change MAC, Heimdall normally asks the router's DHCP
server whether that is an ordinary lease reassignment. Passive mode has no
DHCP server to ask (`HAS_DHCP_LEASES = False`), and the ARP table cannot stand
in for it, because ARP is exactly what a spoofer poisons. The check is skipped
and the change is treated as suspicious. **Expect an occasional `ARP_SPOOF`
alert on a genuine DHCP reassignment in this mode.** Nothing is auto-blocked
(blocking is unsupported), so the cost is a false alert, not an outage.
Fix: a future DHCP-ACK sniffer could supply lease data.

## Configuration

| Setting | Default | |
|---|---|---|
| `PASSIVE_SWEEP_INTERVAL_S` | `300` | `0` disables sweeps (ARP-table-only) |
| Settings → sniff interface | `SNIFF_IFACE` | Must be the LAN-facing interface |

Needs the host network namespace, `nmap` and `iproute2`; the backend container
already has all three, and `NET_RAW` for ARP sweeps. Run outside Docker, nmap
without root still works but reports no vendor, and finds hosts via TCP probes
that fill the ARP table (picked up by the next poll).

## Design notes

* `PassiveAdapter` subclasses `RouterAdapter` directly, not `HttpRouterAdapter`:
  it has no HTTP client.
* The sweep runs as a background task so a slow scan never delays a poll cycle;
  its results appear on the next poll.
* Commands go through an injectable runner and a clock, so the tests need
  neither nmap nor root nor a real network.
* Selecting passive saves a `router_profiles` row with no host and no secret.
  It is offered as a primary router once picked, and cannot be removed while it is
  the primary.
