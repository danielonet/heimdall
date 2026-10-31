---
title: On your phone
description: Using the dashboard on a small screen.
---

The dashboard has two layouts. On a screen up to 768 pixels wide it switches to the phone layout by itself; on anything wider you get the full layout with the top menu. Add `?mobile=1` to the address to force the phone layout on any screen, or `?mobile=0` to force the full one.

In the phone layout:

- The **NOC / SOC** switch sits under the title, next to the status pills (see [Dashboard](/manual/dashboard/)).
- A row of tabs at the top (Overview, Devices, Alerts, Threats, Rules, Reports, Equipment) scrolls sideways.
- A bar at the bottom has **Home**, **Devices**, **Alerts**, **Threats** and **Config** (the Settings page).
- The overview shows the same figures as the full dashboard as four tiles in two columns (devices online, open alerts, threat score, services active), then your connected devices.

Wide tables, such as the alert summary on Reports, scroll sideways inside their own box instead of stretching the page. On Rules, each device-type profile is shown as a block with its three thresholds side by side.

The Map, Ports and WiFi pages have no tab on a phone. You can still open them by adding `/map`, `/ports` or `/wifi` to the address.
