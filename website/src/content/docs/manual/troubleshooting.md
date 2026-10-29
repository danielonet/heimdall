---
title: Troubleshooting
description: Common problems and fixes.
---

## I cannot open the dashboard
Check that Heimdall is running: `sudo heimdall status` (.deb) or `docker compose ps` in the install folder. Use port 3000 on the Heimdall machine's address, from a device on the same network.

## I forgot the admin user name or password
Heimdall cannot show you the password: only a hash of it is stored. To start over, remove the admin account (your data is kept), then create a new one in the browser:

- **.deb install:** `sudo heimdall reset-login`
- **Script install:** in the install folder, run `docker compose exec -T postgres psql -U sentinel -d sentinel -c "DELETE FROM admin_account"`, empty `secrets/admin_password.txt`, then run `docker compose restart sentinel-backend`.

Then open the dashboard and create the account straight away, because the page is open to anyone who can reach it until you do.

An install made before the admin account existed signs in with `admin` and the password in `secrets/admin_password.txt` (`sudo heimdall password` on a .deb install). The same steps switch it to the new account system.

## The device list is empty
You have not chosen a router, or the router login is wrong. Open [Equipment](/manual/equipment/). If your router is not listed, choose **Other / not listed (passive mode)**.

## ARP Watch, DHCP Watch or Passive Fingerprint show OFF
They listen on one network card, and it is probably the wrong one. Open [Equipment](/manual/equipment/), choose the card connected to your home network under **Network interface**, and press **Save**. They start immediately. If you chose it correctly and they still stay off, run `sudo heimdall logs` (.deb) or `docker compose logs sentinel-backend` and look for a line beginning "failed to sniff on".

## WiFi Monitor shows OFF
That is normal until you add a second WiFi adapter that supports monitor mode and choose it under **WiFi monitor** on [Equipment](/manual/equipment/). See [WiFi scan](/manual/wifi-scan/).

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
