---
title: Devices
description: "The inventory, a device page, and setting a device's status: trusted, suspect, quarantined or blocked."
---

## The list

Every device Heimdall has seen, one row each, with its name and IP address, vendor, kind of device, current traffic, WiFi or ETH (plus which access point or segment), signal strength or router port, and a **Status** drop-down.

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
- The **status drop-down** next to the device's badges is where you decide what to do about it (see below). The [Reports](/manual/reports/) page lists each device's trust next to its traffic.
- **Traffic (24h)** and **Anomaly score** charts. They stay empty until the device has some history. A wired device on a router that only counts per port shows a note instead of invented numbers.
- **Open ports (last Nmap scan)**, from the nightly scan. It says so if no scan has run yet.
- **Alert history** for this device, with OPEN, ACKED or RESOLVED.
- A randomised MAC address (the private address phones use per network) has no manufacturer to look up, so the vendor may show as a dash.

## Status: trusted, suspect, quarantined or blocked

One drop-down sets what Heimdall does about a device. It is on every row of the Devices list (phone and full layout) and on the device's own page.

| Status | Effect |
|---|---|
| **Trusted** | A device you know. Nothing is done to it. |
| **Suspect** | Not trusted yet. This is how a new device starts. Nothing is cut off. |
| **Quarantined** | Cuts internet access but leaves the device reachable on your LAN. |
| **Blocked** | Removes the device from the network entirely. Asks you to confirm first. |

Choosing **Trusted** or **Suspect** on a blocked or quarantined device lifts the block or quarantine first. Choosing **Quarantined** on a blocked device unblocks it first. A device that is both blocked and quarantined shows as **Blocked**. Choosing **Quarantined** or **Blocked** leaves your trust decision as it was, so unblocking returns the device to the trust it had.

Blocking and quarantine are carried out by your router, so they only work if your router's adapter supports them. In passive mode they are unavailable; use the router's own admin page. See [Equipment](/manual/equipment/). The [Dashboard](/manual/dashboard/) still has a one-click **Block** button on each connected host.
