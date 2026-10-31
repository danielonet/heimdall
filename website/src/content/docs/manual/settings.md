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
| **Notifications** | **Push** through ntfy.sh (paste a topic URL), a **Telegram** channel (a bot token and a channel; see below) and **email** through SMTP (server, port, STARTTLS, username, password, from, and an optional to). All get the same events: an immediate message when a CRITICAL alert fires, and a daily digest at 7 am covering everything else, with an all-clear on a quiet day. Leave a channel blank to turn it off. Changes apply at once. |

**Log out** is at the bottom of the page and on the top bar.

## Send alerts to a Telegram channel

Heimdall can post its alerts to a Telegram channel or group through a bot that you create yourself. Nothing is shared with anyone else: the bot and its token are yours. The text of each alert (its title, the device and the advice) travels through Telegram's servers, so use this only if you are comfortable with that; it is the one notification channel besides ntfy.sh and email that sends alert text to a third party.

1. **Create the bot.** In Telegram, open a chat with **@BotFather** and send `/newbot`. Choose a display name (for example "Heimdall Alerts") and a unique user name that ends in `bot`. BotFather answers with a **token** that looks like `123456789:AAH…`. Treat it like a password: anyone holding it can post as your bot.
2. **Create the channel.** Make a new channel (or use a group). A private channel is fine.
3. **Let the bot post.** In the channel's settings open **Administrators**, choose **Add administrator**, search for your bot's user name and add it with permission to **post messages**. A bot cannot post to a channel it is not an administrator of.
4. **Find the channel.** A public channel is identified by its link name, for example `@myhomealerts`. A private channel has no name, so use its numeric id, which starts with `-100`. To find it, post any message in the channel, then open `https://api.telegram.org/bot<YOUR TOKEN>/getUpdates` in a browser (replace `<YOUR TOKEN>` with your token) and look for `"chat":{"id":-100…`. Anyone who sees that address sees your token, so do not share a screenshot of it.
5. **Enter both in Heimdall.** On **Settings → Notifications → Telegram** paste the **bot token** and the **channel or chat**, then press **Save**.
6. **Check it.** Press **Send test message**. A green "Sent" means a message arrived in the channel. A red message gives the reason Telegram returned, for example "chat not found" (wrong channel) or "Forbidden: bot is not a member of the channel chat" (step 3 was missed).

The token is stored in a secret file on the Heimdall machine, never in the database, and is not shown again after you save it (the box then shows dots). To replace it, paste a new one and save; to stop using Telegram, clear the channel field and save. On an installation that was upgraded from an earlier version, run `sudo heimdall upgrade` (or `./setup.sh` from the install folder) once so the token file exists.
