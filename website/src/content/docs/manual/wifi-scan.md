---
title: WiFi scan
description: Nearby WiFi devices and networks.
---

:::caution[Draft]
Written from the dashboard's source code. It has not yet been checked page by page against a running dashboard, so a label may differ slightly.
:::


Lists what Heimdall hears over the air.

- **Nearby WiFi devices:** MAC, status, vendor, likely device, the network name it last asked for, signal, strongest signal, times seen, first and last seen. Markers show a device you marked as yours, or one that shares a MAC or manufacturer prefix with a device Heimdall already knows (likely its WiFi adapter).
- **Nearby WiFi networks:** name, likely device, BSSID, vendor, band and channel, security, signal. Mark your own networks as **MINE**.

:::note
Heimdall does not detect rogue access points ("evil twins"). See the [limits](/security/limits/).
:::
