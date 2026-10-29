---
title: Settings
description: Learning, auto-block, alerts, notifications and data.
---

Settings is one page of panels. Each has its own **Save** button, which stays greyed out until you change something.

| Panel | What it does |
|---|---|
| **Anomaly detection** | Shows **LEARNING** while Heimdall builds a traffic baseline. Until a device has cleared the **learning period** (72 hours by default) it is exempt from volume alerts. The other defences stay active meanwhile, and the panel lists them with their state. Expected after a fresh install or a purge. |
| **Auto-block on threat** | When ticked, ARP Watch, Passive Fingerprint and the Nmap scanner block the offending device the moment they detect an attack (spoofing, a fingerprint mismatch, a new high-risk port, a vulnerability) instead of only alerting. **It is ticked on a new install**, so untick it if you would rather decide yourself. An automatic block is timed, lifts itself after 24 hours by default and sends a review notice. One switch covers all eligible alert types. |
| **Alert lifecycle** | *Stale after* (24 hours by default) hides an inactive unresolved alert from the dashboard and map, though it stays open on the Alerts page. *Auto-resolve after* (72 hours) closes alerts that have no natural "this stopped" signal. You can reopen one from the Alerts page. |
| **Reset & relearn** | **Purge database…** deletes every known device, trust decision, traffic history, alert and trained model, and returns to learning. It asks you to confirm and cannot be undone. |
| **Data retention** | How long to keep traffic, port statistics, WAN changes and alerts (90 days by default), when an idle device is archived and hidden from counts (90 days), and when an archived device is permanently deleted (a further 90 days). Trusted, blocked and quarantined devices are exempt from archiving. It also shows the database size and lists archived devices so you can restore them. |
| **Notifications** | **Push** through ntfy.sh (paste a topic URL) and **email** through SMTP (server, port, STARTTLS, username, password, from, and an optional to). Both get the same events: an immediate message when a CRITICAL alert fires, and a daily digest at 7 am covering everything else, with an all-clear on a quiet day. Leave a channel blank to turn it off. Changes apply at once. |

**Log out** is at the bottom of the page and on the top bar.
