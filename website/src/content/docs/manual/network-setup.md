---
title: "Guide: router, access point and evil twin"
description: "Set up your router and a second access point so Heimdall can see everything, and protect your WiFi name from an evil twin."
---

This guide covers the network *around* Heimdall: how to connect a router and an access point (AP) so Heimdall sees every device, and how to make Heimdall tell you when someone copies your WiFi name. It does not repeat the dashboard pages; for those see [Equipment](/manual/equipment/) and [WiFi scan](/manual/wifi-scan/).

:::note
Router menus differ between makes and firmware versions, so the steps below name the setting you are looking for, not the exact button. Where Heimdall behaviour is described it is what the program does today; what is not built yet is labelled **planned**.
:::

## What you are building

```
Internet ─ ISP router (primary: DHCP, firewall) ─┬─ Heimdall machine (cable)
                                                 ├─ Wired devices
                                                 └─ cable ─ Access point (AP mode: WiFi only)
```

- **One router** hands out addresses and connects you to the internet. Heimdall signs in to this one (the *primary router*) to read devices and traffic, and to block or quarantine.
- **Any extra WiFi box** is an **access point**: it adds WiFi coverage but does not hand out addresses. Heimdall sees its WiFi devices on the same network as everything else.
- **The Heimdall machine** is wired to the router. A cable is strongly preferred over WiFi, because the sensors that watch for ARP spoofing and rogue DHCP servers need to see the network's broadcast traffic.

## Part 1. Set up a second router as an access point

Skip this part if you only have one router. If you already own a second router and want to reuse it for coverage, switch it to **AP mode** (some firmware calls it *bridge mode*). Left in normal router mode it creates a second network behind the first ("double NAT"), and Heimdall will only see the devices on the first one.

1. **Reset or open the second router's admin page** and find the setting for **Working mode**, **Operation mode** or **Bridge / AP mode**. Choose AP (bridge).
2. **Give it a fixed address on your main network.** Pick one on the main router's network but outside its DHCP range: if the main router is the `.1` address and hands out addresses from `.100` upwards, the AP can take `.2`. Write it down: this is how you reach the AP's admin page later.
3. **Turn off its DHCP server.** The main router must be the only one handing out addresses. Two DHCP servers on one network cause random connection failures, and Heimdall's Rogue DHCP Watch will rightly raise an alert about the second one.
4. **Connect it by cable** from one of its LAN ports to a LAN port on the main router (or a switch). Do not use its WAN/Internet port in AP mode. A wired link is faster and more reliable than a wireless repeater.
5. **Set the WiFi.**
   - Use **WPA2-PSK (AES)** or **WPA3** with a long passphrase. Do not use WEP, WPA/TKIP or an open network.
   - Turn **WPS off**.
   - Use the **same network name and password** as the main router if you want phones to roam between them, or a different name if you prefer to choose. Both work with Heimdall.
   - Pick different channels from the main router. On 2.4 GHz the non-overlapping channels are **1, 6 and 11**.
6. **Change the AP's admin password** from the factory default, and turn off remote administration.
7. **Tell Heimdall about it.** If the AP is a router family Heimdall supports, add it on [Equipment](/manual/equipment/) with **Routers** and save its login, so Heimdall can read which WiFi devices are connected to it. Heimdall can read some routers in AP mode; check the [equipment table](/equipment/) for yours. If it is not listed, nothing is lost for security: ARP Watch and the other sniffer-based sensors still see the AP's devices because they are on the same network.

:::tip
Check it worked: connect a phone to the AP's WiFi, then open **Devices** in Heimdall. The phone should appear within a minute with an address from your main router's range. If its address starts with a different number, the AP is still in router mode (step 1).
:::

## Part 2. What an evil twin is

An **evil twin** is a fake access point that broadcasts *your* WiFi name. Phones and laptops that already know your network join the strongest signal with that name, so a device close to the attacker connects to it by itself. The attacker can then read unencrypted traffic, redirect web pages or ask for passwords. Strong WPA2 or WPA3 on your own access point does not stop it, because the twin is a different access point that the attacker controls.

## Part 3. How Heimdall spots one

Every access point puts out a short announcement several times a second containing its network name and a unique hardware address called a **BSSID**. Heimdall's WiFi monitor listens for these announcements. If it hears one of your **protected network names** coming from a BSSID that is **not on your list of trusted access points**, it raises a **CRITICAL ROGUE_AP** alert.

Two lists make this work:

| List | Holds | Example |
|---|---|---|
| **Protected network names** | Your own WiFi names (SSIDs), including a guest network | `HomeWiFi`, `HomeWiFi-Guest` |
| **Trusted access points** | The BSSID of every radio of every access point you own | one per band and per name |

An access point has a separate BSSID for each radio (2.4 GHz and 5 GHz) and for each name it broadcasts (main and guest), so a dual-band router with a guest network usually has four. Leave one out and Heimdall will raise a false alarm on your own gear.

### What you need

- A **second WiFi adapter that supports monitor mode**, plugged into the Heimdall machine. It must be dedicated to listening: it cannot be the adapter that connects the machine to your network.
- Heimdall running and, ideally, a router it can read (for the automatic detection below).

Rogue-AP detection is **off until you set it up**. Without the adapter nothing is overheard.

### Set it up

1. Open **Equipment → WiFi monitor** and choose the monitor adapter. Press **Save**.
2. Press **Detect from my router**. Heimdall reads your WiFi names from the router and lists every access point the adapter can hear using those names, with address, channel and signal.
3. Read the list line by line. Lines from the same manufacturer as your router are ticked for you. Anything marked **different maker — check it is yours** needs a check: it may be your second AP, or it may be the very thing you are trying to catch. Tick a line only when you know the device is yours. Walk around with a phone and compare if you are unsure.
4. Press **Use these**, then **Save**.
5. If a name says **not heard yet**, wait a minute and press the button again; the adapter listens to the channels one after another.
6. Open the [WiFi scan](/manual/wifi-scan/) page and mark your own networks as **MINE** so you can tell them from your neighbours' at a glance.
7. **Do not add an access point you do not own to the trusted list**, even if it carries your WiFi name, or the check will stay silent for it.

Add the BSSIDs of any access point you buy later, and remove one that you retire. Otherwise a new AP triggers a false alert, and an old address left on the list could be copied by an attacker.

### If you get a ROGUE_AP alert

1. Look at the alert: it names the network and the BSSID that is not yours.
2. Check the obvious cause first: **did you just add or reset an access point**? A router restored to factory settings, or a new AP, shows a new BSSID.
3. Check **Nearby WiFi networks** for the signal strength. A strong signal means the device is close to your home.
4. If you do not recognise it, do not join it. Look for an unknown device plugged in nearby, or a phone hotspot named like your network. Change your WiFi password if any of your devices may have connected to it.
5. Heimdall cannot block an access point it does not control. The alert is the whole response.

### Honest limits

- It is a **listener**, not a shield. It tells you after the twin appears; it cannot stop devices from joining it.
- It needs the extra adapter, and it is off by default.
- Published coverage is **2.4 GHz channels 1, 6 and 11**. An access point on another channel or band can be missed. See [known limits](/security/limits/).
- An attacker who copies your BSSID as well as your name is not distinguishable by this check.
- It cannot see a twin that is not in range of the Heimdall machine.

## Part 4. Reduce the risk without Heimdall

These cost nothing and work on any router:

- Use **WPA3** (or WPA2-AES) and a long passphrase; turn WPS off.
- Keep **guest devices on a guest network** with client isolation on, so they cannot reach your computers.
- Keep router firmware up to date and the admin page off the internet.
- On devices you carry, turn off **auto-join** for networks you do not need, and use a VPN on WiFi you do not control.

## Part 5. Managed switch

:::note[Draft]
This part has not yet been checked against a running dashboard.
:::

Why it matters: a router only reports wired traffic per **port**, not per device, so devices behind a switch share one router port and Heimdall shows them with port-level counters and says so. A managed switch counts traffic on each of its own ports and knows which device sits on each, so a device that is alone on a switch port can get its own figures.

**Which switches.** Only the models in [the switch table](/equipment/#switches), and only those with a web page for port statistics and a MAC address table. Today that is the HC-SWTGW218AS. If yours is not listed, test fixtures from your switch's pages are one of the most useful contributions; see [Contribute](/contribute/).

1. **Put the switch on your network** and give it a fixed address (a DHCP reservation on your router, or a static address on the switch), so Heimdall can always find it.
2. **Plug the switch's uplink into your router.** The port that leads to your router will carry many devices, so it stays a port total; that is expected.
3. **Plug the Heimdall machine and the devices you care about into other ports.** A device alone on a port is the case that gets its own figures. A device behind an access point or a second switch shares that port and does not.
4. **If the switch has a user setting,** use an account that can only read, and a long password that is not used anywhere else. Some switches log in with a plain hash sent over HTTP, so anyone on your network who sees one request can reuse the login (see [Known limits](/security/limits/)).
5. **Add it on [Equipment](/manual/equipment/#switches):** **+ ADD A SWITCH**, then **Save & test**. The result tells you how many ports are up and how many have exactly one device.
6. **Wait for the second poll** (about 15 seconds). Open **Ports** to see each port, and a device's detail page to see its own traffic.

What it shows and its limits:

- Only a port with exactly one device is credited to that device. A port shared by several is a total.
- The figures are the port's counters, slightly higher than the data the device itself moved.
- Heimdall reads the switch; it does not change it, and it cannot block a device at the switch.
