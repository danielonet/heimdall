---
title: First login
description: Sign in to the dashboard and finish setting up.
---

1. Open `http://<this-machine>:3000` from any computer on your home network.
2. Sign in with the user name and password you chose during installation. The installer asks for both on a fresh install: a user name of 3 to 32 letters, digits, dots, dashes or underscores, and a password of at least 12 characters. If you pressed **Enter** at the prompts, the user is `admin` and the password was generated for you: run `sudo heimdall password` (.deb install) or read `secrets/admin_password.txt` in the install folder (script install).
3. Open the **Equipment** page and choose your router, or **Other / not listed (passive mode)** if yours is not in the list. See [Equipment](/manual/equipment/).
4. Still on **Equipment**, check **Network interface**. It must be the network card connected to your home network. If the sensors named ARP Watch, DHCP Watch and Passive Fingerprint show **OFF** on the [Dashboard](/manual/dashboard/), this is a common reason; pick the right one and press **Save**, and they start at once.
5. Leave Heimdall running. It spends a **learning period** getting to know each device before the anomaly detector starts judging them (see [Settings](/manual/settings/)).

:::danger[Do not expose it]
Never forward ports 3000 or 5000 to the internet. To reach Heimdall away from home, use a VPN you already trust.
:::
