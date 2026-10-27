---
title: Devices
description: The inventory, a device page, trust, block and quarantine.
---

## The list

Every device Heimdall has seen, one row each, with its name and IP address, vendor, kind of device, current traffic, WiFi or ETH (plus which access point or segment), signal strength or router port, trust, and a **Block** button.

Above the table:

- A **search box** for name, IP address or MAC address.
- **Connectivity:** all, online or offline.
- **Network:** all, WiFi or wired.
- **Trust:** all, trusted or suspect.
- **Presence:** all, connected, or *nearby only* (devices heard over the air that never joined your network).
- **Group by AP** gathers the rows by access point.

The count on the right ("12 / 12 devices") shows how many rows match your filters.

## A device's page

Click a device to open it.

- **Rename** changes the name Heimdall shows. The router's own name is offered as a hint.
- The **TRUSTED / SUSPECT** badge is a button: click it to change whether you trust the device. The [Reports](/manual/reports/) page lists each device's trust next to its traffic.
- **Traffic (24h)** and **Anomaly score** charts. They stay empty until the device has some history. A wired device on a router that only counts per port shows a note instead of invented numbers.
- **Open ports (last Nmap scan)**, from the nightly scan. It says so if no scan has run yet.
- **Alert history** for this device, with OPEN, ACKED or RESOLVED.
- A randomised MAC address (the private address phones use per network) has no manufacturer to look up, so the vendor may show as a dash.

## Block and quarantine

| Action | Effect |
|---|---|
| **Block** | Removes the device from the network entirely. |
| **Quarantine** | Cuts internet access but leaves the device reachable on your LAN. |
| **Unblock** / **Unquarantine** | Reverses either. |

Both are carried out by your router, so they only work if your router's adapter supports them. In passive mode they are unavailable; use the router's own admin page. See [Equipment](/manual/equipment/).
