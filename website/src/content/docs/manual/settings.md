---
title: Settings
description: Learning, auto-block, alerts, notifications and data.
---

Settings is one page of panels. Each has its own **Save** button, which stays greyed out until you change something.

| Panel | What it does |
|---|---|
| **Anomaly detection** | Shows **LEARNING** while Heimdall builds a traffic baseline. Until a device has cleared the **learning period** (72 hours by default) it is exempt from volume alerts. The other defences stay active meanwhile, and the panel lists them with their state. Expected after a fresh install or a purge. |
| **Auto-block on threat** | The same switch as **NOC / SOC** in the header (see [Dashboard](/manual/dashboard/)). When ticked (SOC), ARP Watch, Passive Fingerprint and the Nmap scanner block the offending device the moment they detect an attack (spoofing, a fingerprint mismatch, a new high-risk port, a vulnerability) instead of only alerting. **It is not ticked on a new install**: Heimdall starts in NOC mode and only alerts, so tick it (or switch to SOC in the header) once you trust what it reports. An upgrade keeps the mode you already had. An automatic block is timed, lifts itself after 24 hours by default and sends a review notice. One switch covers all eligible alert types. |
| **Alert lifecycle** | *Stale after* (24 hours by default) hides an inactive unresolved alert from the dashboard and map, though it stays open on the Alerts page. *Auto-resolve after* (72 hours) closes alerts that have no natural "this stopped" signal. You can reopen one from the Alerts page. |
| **Reset & relearn** | **Purge database…** deletes every known device, trust decision, traffic history, alert and trained model, and returns to learning. It asks you to confirm and cannot be undone. |
| **Data retention** | How long to keep traffic, port statistics, WAN changes and alerts (90 days by default), when an idle device is archived and hidden from counts (90 days), and when an archived device is permanently deleted (a further 90 days). Trusted, blocked and quarantined devices are exempt from archiving. It also shows the database size and lists archived devices so you can restore them. |
| **Notifications** | **Push** through ntfy.sh (paste a topic URL), a **Telegram** channel (a bot token and a channel) and **email** through SMTP (server, port, STARTTLS, username, password, from, and an optional to). All get the same events: an immediate message when a CRITICAL alert fires, and a daily digest at 7 am covering everything else, with an all-clear on a quiet day. Leave a channel blank to turn it off. Changes apply at once. Each channel has a test button (see below). Setup walk-throughs are in [Guide: set up notifications](/manual/notifications-setup/). |

**Log out** is at the bottom of the page and on the top bar.

## Check that a channel works

Each channel on **Settings → Notifications** has its own test button: **Send test** (ntfy), **Send test message** (Telegram) and **Send test email**. Each one sends a short message through the settings you have already **saved** (the button is greyed out while there are unsaved changes, so save first) and shows a green "Sent" or a red reason underneath. The reason is in plain words, for example that the mail server rejected the password, that the server could not be reached, or that the topic address is wrong. It never shows your password, token or topic address. A green result means the message left Heimdall and the service accepted it; for email, still look in the inbox and the spam folder.

## Email, Telegram and push

Step-by-step setup for each channel, including a Gmail example, the Telegram bot and ntfy, is in [Guide: set up notifications](/manual/notifications-setup/).
