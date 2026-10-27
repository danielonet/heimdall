---
title: Rules
description: Your own detection rules, device-type profiles and the port allowlist.
---

:::caution[Draft]
Written from the dashboard's source code. It has not yet been checked page by page against a running dashboard, so a label may differ slightly.
:::


## Detection rules

**+ NEW RULE** opens the rule editor. A rule has a device type, a **trigger field**, an **operator** and a **value**, an **action**, a **severity**, an optional **tag**, and **quiet minutes** (how long to stay silent after firing). Save the rule first, then use the dry-run test to see what it would have matched. A rule whose action is *block device* can block automatically.

## Device type profiles

The thresholds the built-in detectors use per kind of device (a NAS is expected to upload more than a phone). The page shows the most extreme values actually measured on your network, refreshed hourly, so you can tune from facts.

## Port allowlist

Tell Heimdall that a port on a device is expected, so it stops raising high-risk-port alerts for it.
