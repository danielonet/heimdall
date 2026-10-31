---
title: Dashboard
description: The overview page.
---

The first page after you sign in. It updates live; you do not need to refresh it.

- **NOC / SOC switch (in the header on every page).** Shows which mode Heimdall is in. **NOC** only watches: detectors raise alerts and nothing is blocked for you. **SOC** also responds: ARP Watch, Passive Fingerprint and the Nmap scanner block the offending device the moment they detect an attack. Click the other name to switch; switching to SOC asks you to confirm because it can cut a device off your network. The switch is the *Auto-block on threat* setting on the [Settings](/manual/settings/) page, so the two always agree, and a new install starts in **NOC**, so nothing is blocked until you choose SOC. An upgrade keeps the mode you already had. A block it makes is timed and lifts itself after 24 hours by default. It does not change what is detected or alerted on, and blocking still depends on your router's adapter supporting it.

- **Three tiles across the top.** *Devices online*, *Active alerts* (it says REVIEW when there is anything to look at and CLEAR when there is not) and *Threat score*. The score is a simple weighted count of unresolved alerts shown (critical 20, warning 8, info 2, capped at 100) and reads RISK above 40. It is a quick summary, not a measurement of how safe you are.
- **Connected hosts.** Every online device with its vendor, current upload and download, WiFi or ETH, and a **Block** button. Wired devices show a dash instead of a speed when your router only counts bytes per port, because that figure would belong to the port and not to one device. See [Devices](/manual/devices/).
- **Bandwidth usage.** The busiest devices right now.
- **Open alerts.** Open alerts, with a link to the device. Alerts older than the *stale after* setting are left out here, though they stay on the [Alerts](/manual/alerts/) page. A critical alert is picked out in a panel beside the list. Click an alert to show it there.
- **Ports.** The router's physical ports and their link state. See [Ports](/manual/ports/).
- **Services.** One line per part of Heimdall: Postgres, Redis, your router adapter and each sensor, with its state (OK, POLLING, PENDING, OFF, or when it last ran). Hover a line for what that part does, plus its version and database size (Postgres) or memory use (Redis) and the time of its last alert. A sensor that shows OFF is not running; see [Troubleshooting](/manual/troubleshooting/) if you expected it to be.
