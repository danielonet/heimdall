---
title: Settings
description: Learning, auto-block, alerts, notifications and data.
---

:::caution[Draft]
Written from the dashboard's source code. It has not yet been checked page by page against a running dashboard, so a label may differ slightly.
:::


Settings is a grid of tiles.

| Tile | What it does |
|---|---|
| **Learning status** | The learning period before anomaly detection judges a device. **Reset & relearn** starts it again. |
| **Auto-block on threat** | Off by default. When armed, a threat alert that qualifies blocks the device automatically. An automatic block is timed and expires, then sends a review notice. One switch covers all eligible alert types. |
| **Alert lifecycle** | *Stale after* hides old alerts from the dashboard feed; *auto-resolve after* closes them. |
| **Data retention** | Retention window, archive-after and delete-after for devices. Deleting is permanent. |
| **Purge database** | Wipes recorded data. Asks you to confirm; cannot be undone. |
| **Notifications** | Push through ntfy.sh (a topic URL) and email through SMTP. A daily digest summarises alerts, with an all-clear message on a quiet day. |
| **WiFi monitor** | Protected network names and your access points' real MAC addresses, so Heimdall can tell yours from lookalikes. |

**Log out** is at the bottom.
