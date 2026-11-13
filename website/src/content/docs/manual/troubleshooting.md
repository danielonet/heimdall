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

If the list was fine and then went empty, the connection to the router was probably lost. Heimdall keeps polling every 15 seconds. After four failed polls in a row because the router cannot be reached, it also builds a fresh connection (looks up the router address again, re-reads the saved password and logs in again). It tries again after 1 minute, then 2, 4, 8 and up to 15 minutes while the router stays unreachable. This happens only when a password is saved for that router, and never after a rejected password or when the router has locked Heimdall out, because repeating those logins would keep it locked. For those, fix the password on Equipment and Heimdall continues on its own.

## A switch shows "Not reporting"
Open [Equipment](/manual/equipment/#switches): the reason is printed under the switch.

- **"the switch rejected the login"**: the user name or password is wrong. Edit the switch and enter the right password. Heimdall will not try again until you do, because repeated wrong logins can lock a switch's admin account.
- **"no answer" or a timeout**: the switch is off, has a different address, or is not reachable from the Heimdall machine. Check the address (a DHCP reservation keeps it fixed) and try **Test**.
- **"the switch layout may have changed"**: the switch answered, but a page no longer looks the way Heimdall expects, usually after a firmware update. Heimdall shows this instead of showing zeros. Report it with the firmware version.
- **"is not a private-LAN address"**: Heimdall only talks to switches on your local network.
- **A port shows "N devices · port total" and no device**: more than one device is behind that port (an uplink, an access point). That is correct. Only a port with exactly one device is credited to it.
- **Some devices never get their own figures**: they are behind a shared port, or the switch has not learned them yet because they have not sent anything.

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

## The machine freezes, or containers restart again and again, with no swap
On a small machine (about 4 GB, as on many single-board computers) the **full** tier runs the database, Suricata, Zeek, ClamAV and the backend side by side, and a Linux machine with no swap goes straight from "full" to the kernel killing a process. Signs: `dmesg | grep -i "out of memory"` names `gunicorn` or another container's process, `docker stats --no-stream` shows one container near its limit, and the load average is far above the number of cores.

- Every container has a memory cap, so a runaway one is killed and restarted alone instead of taking the machine down. The installer sizes the caps for the RAM it finds (table below). A machine installed before this existed gets them the next time you run `./setup.sh` (.deb: `sudo heimdall setup`); caps you have edited are kept. `docker stats --no-stream` shows each container's use against its cap. Raise one in `.env` if a healthy container is killed, for example `BACKEND_MEM_LIMIT=2g`, then `docker compose up -d`. The names are `BACKEND_`, `POSTGRES_`, `CLAMAV_`, `SURICATA_`, `ZEEK_`, `REDIS_`, `OPENCANARY_` and `FRONTEND_` followed by `MEM_LIMIT`.
- Add a swap file so a short spike is slow instead of fatal: `sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile`, and add `/swapfile none swap sw 0 0` to `/etc/fstab` to keep it after a reboot. On an SD card or eMMC, swap wears the storage, so use it as a safety net, not a daily workspace.
- If 4 GB is all you have, use the **intermediate** tier (no Suricata, Zeek or ClamAV): set `DEPLOYMENT_TIER=intermediate` and `COMPOSE_PROFILES=intermediate` in `.env`, then `docker compose up -d --remove-orphans`.
- Older versions of the backend read Zeek's `conn.log` whole on every beacon scan, and `conn.log` is never rotated, so the backend's memory grew with the size of that file. It now reads a bounded window, and the other log readers and the file scan are bounded too. If you see one backend process near 2 GB, upgrade first.

### Memory caps by RAM

These are ceilings, not reservations: they add up to more than the RAM on purpose, because only the container that grows is stopped. The sizes are estimates, not measurements on every kind of machine; tighten or raise them from `docker stats`.

| Detected RAM | Counts as | Backend | Postgres | ClamAV | Suricata | Zeek | Redis | OpenCanary | Frontend |
|---|---|---|---|---|---|---|---|---|---|
| under 6 GB | 4 GB | 1.5 GB | 1.5 GB | 2 GB | 768 MB | 768 MB | 256 MB | 256 MB | 128 MB |
| 6 to 12 GB | 8 GB | 2 GB | 2 GB | 2 GB | 1 GB | 1 GB | 256 MB | 256 MB | 128 MB |
| 12 to 24 GB | 16 GB | 3 GB | 4 GB | 2.5 GB | 1.5 GB | 2 GB | 512 MB | 256 MB | 256 MB |
| 24 GB and up | 32 GB | 4 GB | 8 GB | 3 GB | 2 GB | 4 GB | 1 GB | 512 MB | 256 MB |


## Upgrading
Script install: run the install command again. .deb: install the newer package. Your data and secrets are kept, and the images of the older versions are removed afterwards (see [Upgrade](/manual/upgrade/#older-images-are-removed)).

## The installer stops with "Not enough disk space"
Before it writes or downloads anything, the installer adds up the images of the tier you chose (the ones not already on the machine) plus a 1 GB reserve for the system and the database, and compares that with the free space on the disk that holds Docker's data. If it does not fit it prints the free space, the space needed and the shortfall, and exits without changing anything. Free some space (for example `docker system prune`, which removes unused images and stopped containers) or use a bigger disk, then run it again. If you have upgraded Heimdall before, `./setup.sh --prune-old-images` in the install folder removes the images of its older versions. A smaller tier may fit: the message says so when it does. The sizes are approximate; if you are sure there is room, `--skip-disk-check` skips the check.

