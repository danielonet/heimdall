---
title: Equipment
description: Choose your router, enter its login, and set the primary router.
---

:::caution[Draft]
Written from the dashboard's source code. It has not yet been checked page by page against a running dashboard, so a label may differ slightly.
:::


## Add a router

Pick your router family from the list, enter its address and login, and save. The password is kept in a secret file on the Heimdall machine, never in the database. Routers marked **PLANNED** can have a login saved but cannot be polled yet. **Other / not listed (passive mode)** needs no login (see below).

## Primary router

Heimdall reads devices from one **primary router** at a time. Once you have added more than one, choose which is primary here.

## Router details

For the primary router: model, firmware, serial, WAN IP, WAN MAC, WAN status and mode, uptime, deployment, SSIDs and WiFi radios, where the router reports them.

## Passive mode

With **Other / not listed**, Heimdall builds the device list from its own view of the network. You get inventory, new-device alerts and every sniffer-based detector. You do not get per-device traffic, WAN statistics, or block and quarantine. See [what works without a supported router](/equipment/no-router/). Passive mode cannot be removed while it is the primary router.

## Network interface

Set the LAN-facing interface Heimdall sniffs. A wired interface is strongly preferred.
