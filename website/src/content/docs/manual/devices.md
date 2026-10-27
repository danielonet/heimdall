---
title: Devices
description: The inventory, a device page, and block and quarantine.
---

:::caution[Draft]
Written from the dashboard's source code. It has not yet been checked page by page against a running dashboard, so a label may differ slightly.
:::


## The list

Every device Heimdall has seen: MAC, IP, hostname, vendor, device type, signal, traffic, and which WiFi access point it uses. You can filter by search text, connectivity (wired or WiFi), network, trust, and presence (online or not).

## A device's page

Click a device to open it.

- **Rename:** click the name. The router's own hostname is shown on hover.
- **Traffic (24h)** and **Anomaly score** charts. Wired devices on routers that only count per port show a note instead of invented per-device numbers.
- **Open ports (last Nmap scan)** from the nightly scan.
- **Alert history** for this device, with OPEN / ACKED / RESOLVED status.
- A randomised MAC address (the private address phones use per network) is labelled, because it has no real manufacturer prefix to look up.

## Block and quarantine

| Action | Effect |
|---|---|
| **Block** | Removes the device from the network entirely. |
| **Quarantine** | Cuts internet access but leaves the device reachable on your LAN. |
| **Unblock** / **Unquarantine** | Reverses either. |

Both are carried out by your router, so they only work if your router's adapter supports them. In passive mode they are unavailable; use the router's own admin page. See [Equipment](/manual/equipment/).
