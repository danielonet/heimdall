---
title: Rules
description: Your own detection rules, device-type profiles and the port allowlist.
---

## Detection rules

**+ New rule** opens the rule editor. A rule has:

- a **name**;
- a **trigger**: *traffic sample* (each measurement of a device's traffic) or *device snapshot* (the device's current state);
- a **field** to look at (for traffic samples, for example upload or download speed or bytes moved), an **operator** (greater than, less than, equal, not equal, contains, in a list) and a **value**;
- **sustained for**, the number of consecutive polls the condition must hold;
- an **action**: *alert* (with a **severity** of info, warning or critical), *block device*, *notify*, *tag device* (you give the tag) or *rate limit*;
- for *rate limit*, **quiet minutes**: the rule fires, then stays silent for that long, so one noisy device does not flood you. It does not slow the device's traffic;
- an optional tick to also send a push or email notification.

Saved rules appear in a list with an **Enabled / Disabled** switch, **Edit** and **Delete**. Open **Edit** and press **Test (saved version)** to dry-run the rule against recent data: Heimdall reports how many samples it evaluated and how many matched, and lists the matching devices, without raising anything. A new rule must be saved before it can be tested. A rule whose action is *block device* can block automatically, so test it before you rely on it.

## Device type profiles

The thresholds the built-in detectors use per kind of device, since a NAS is expected to upload more than a phone. Each row has three editable numbers: **ratio** (the upload-to-download ratio above which a device counts as a heavy uploader), **polls** (how many polls in a row an unusual volume must last) and **contamination** (the share of readings the anomaly model treats as outliers). Under each number Heimdall shows the largest value it has actually measured on your network, with a link to that device, refreshed hourly, so you can tune from facts. Until a device type has history it says "no data yet". **Save** keeps your override, **Reset** goes back to the default, and **+ Add device type override** adds a type that is not listed.

## Port allowlist

Tell Heimdall that a port on a device is expected, so it stops raising high-risk-port alerts for it. Pick a device and a port from the lists and press **Add**. Adding an entry also resolves any open finding for it and, if the device was auto-blocked because of it, unblocks it.
