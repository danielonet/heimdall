---
title: Troubleshooting
description: Common problems and fixes.
---

## I cannot open the dashboard
Check that Heimdall is running: `sudo heimdall status` (.deb) or `docker compose ps` in the install folder. Use port 3000 on the Heimdall machine's address, from a device on the same network.

## I forgot the admin password
`sudo heimdall password` (.deb), or read `secrets/admin_password.txt` in the install folder.

## The device list is empty
You have not chosen a router, or the router login is wrong. Open [Equipment](/manual/equipment/). If your router is not listed, choose **Other / not listed (passive mode)**.

## Traffic shows "PORT TOTAL" for a wired device
Routers count bytes per port, not per device. Heimdall will not present that as one device's traffic.

## I get a false ARP-spoof alert
In passive mode Heimdall cannot ask a router's DHCP server whether an address change was normal, so an ordinary reassignment can raise `ARP_SPOOF`. Nothing is blocked automatically in passive mode.

## Suricata raises too many alerts
The stock rule set is tuned for enterprise traffic. Add suppressions for the rules that are noisy on your network. See [Suricata](/security/suricata/).

## Something is wrong and I need logs
`sudo heimdall logs` (.deb), or `docker compose logs -f --tail 100` in the install folder.

## Upgrading
Script install: run the install command again. .deb: install the newer package. Your data and secrets are kept.
