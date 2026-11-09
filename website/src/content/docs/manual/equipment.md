---
title: Equipment
description: Your router's details, choosing your router, the network interface and the WiFi monitor.
---

## Router details

At the top: the primary router's model, firmware, serial number, WAN IP and MAC, WAN status and mode, uptime, the deployment tier, its WiFi names (SSIDs) and radios, for whatever the router reports. Passive mode has no router to ask, so most of this is empty.

## Routers

Open the **Routers** list, tick your router family (or **Other / not listed (passive mode)** if yours is not there) and it is added below. Each added router shows its protocol, whether it is **SUPPORTED** or **PLANNED**, whether a login is saved, and a **Login** button. Press it, enter the address or username and the password or API key that router asks for, and press **Save & test**. Heimdall saves the login and then really signs in to the router, and the window shows the result: a green **Signed in to …** message (with the number of devices found), or a red message with the reason the router gave, such as a wrong password or no answer. The window stays open on a failure so you can correct the details and try again. The password goes into a secret file on the Heimdall machine, never into the database, and leaving the box blank later keeps the one you saved. A router marked **PLANNED** can have a login saved but cannot be polled yet. For what each router can do, see the [equipment table](/equipment/).

## Primary router

Heimdall treats one router as the **primary**: threat detection, WAN status and auto-block all run against it. When you have added more than one, choose which is primary here and press **Save**. The other routers are still read for devices and traffic.

## Passive mode

With **Other / not listed**, there is no login. Heimdall builds the device list from its own view of the network (the ARP table and a sweep). You get inventory, new-device alerts and every sniffer-based detector, plus Nmap, Suricata, Zeek and the honeypot where your install includes them. You do not get per-device traffic, WAN statistics, or block and quarantine. See [what works without a supported router](/equipment/no-router/). Passive mode cannot be removed while it is the primary router; choose another primary first.

## Network interface

The network card Heimdall listens on for ARP watch and passive fingerprinting. Pick the one connected to your home network and press **Save**; it applies at once. A wired interface is strongly preferred. If the saved one is not currently present the list says "not currently detected".

## WiFi monitor

The adapter used to listen for nearby WiFi, plus your **protected network names** and your access points' real addresses, which is what lets Heimdall spot an "evil twin" (a fake access point copying your WiFi name). It needs a second WiFi adapter that supports monitor mode. The **Detect from my router** button fills the lists in for you; see [WiFi scan](/manual/wifi-scan/) for how it works and what to check. Press **Save** to keep the changes.

## Switches

:::note[Draft]
This section has not yet been checked against a running dashboard.
:::

A router only counts wired traffic **per port**. A managed switch counts it on each of its own ports, so a device that is alone on a switch port gets its own upload and download instead of the router's PORT TOTAL. Heimdall reads two pages of the switch (the per-port counters and the MAC address table) and credits a port to a device only when exactly one device is learned on it. A port shared by several devices, such as the one that links the switch to your router, stays a port total and is not credited to any of them.

Press **+ ADD A SWITCH**, pick the model, give it a name, its address on your network, its login and how often to read it (default 15 seconds), then **Save & test**. Only the models in [the switch table](/equipment/#switches) can be read. The address must be on your local network: Heimdall refuses a public address. The password is kept in a secret file on the Heimdall machine and is never shown again; leave it blank when editing to keep it.

Each switch shows:

| Field | Meaning |
|---|---|
| **Reporting** | The last read worked. "Last read" says when. |
| **Not reporting** | The last read failed. The reason is shown under it: a wrong password, no answer, or a page that no longer looks the way Heimdall expects (a firmware change). Heimdall retries by itself, waiting longer after repeated failures, but never retries a rejected password until you change it. |
| **Waiting for first poll** | Saved, not read yet. |
| **Ports** | Opens the latest reading of each port: link, speed, the device credited with it (if exactly one), and down and up from the **connected device's** side. A port shared by several devices shows "N devices · port total". |
| **Test** | Logs in once and reports the model, how many ports are up and how many ports have exactly one device. |

A device a switch credits shows the switch and port on its detail page, and its traffic charts fill in. The first read of a switch only sets a starting point, so figures appear after the second.

What to know:

- The numbers are the port's counters, so they include frame headers and broadcast traffic and read slightly higher than the data the device itself sent.
- A device that never transmits is never learned by the switch. If it shares a port with another device, the port is credited to the one that is.
- Heimdall only needs to read the switch. It does not change any setting, and it never touches the switch's "clear" buttons.
- Some switches log in with a plain hash sent over HTTP. See [Known limits](/security/limits/).
