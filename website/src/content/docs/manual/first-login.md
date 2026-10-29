---
title: First login
description: Sign in to the dashboard and finish setting up.
---

1. Open `http://<this-machine>:3000` from any computer on your home network.
2. On a new install the page says **Welcome** and asks you to create your admin account. Choose a user name (3 to 32 letters, digits, dots, dashes or underscores) and a password of at least 12 characters, type the password twice, and press **Create account**. You are signed in straight away. Only a salted hash of the password is stored, in Heimdall's database; no password is written to a file. Do this as soon as Heimdall starts: until it is done, anyone who can reach the page could create the account first.

   An install made before this version keeps signing in as `admin` with the password in `secrets/admin_password.txt` (`sudo heimdall password` shows it on a .deb install).
3. Open the **Equipment** page and choose your router, or **Other / not listed (passive mode)** if yours is not in the list. See [Equipment](/manual/equipment/).
4. Still on **Equipment**, check **Network interface**. It must be the network card connected to your home network. If the sensors named ARP Watch, DHCP Watch and Passive Fingerprint show **OFF** on the [Dashboard](/manual/dashboard/), this is a common reason; pick the right one and press **Save**, and they start at once.
5. Leave Heimdall running. It spends a **learning period** getting to know each device before the anomaly detector starts judging them (see [Settings](/manual/settings/)).

:::danger[Do not expose it]
Never forward ports 3000 or 5000 to the internet. To reach Heimdall away from home, use a VPN you already trust.
:::
