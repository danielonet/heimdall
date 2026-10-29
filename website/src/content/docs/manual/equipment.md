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

Monitoring managed switches for per-device wired traffic is **planned**. The section is there but there is nothing to configure yet.
