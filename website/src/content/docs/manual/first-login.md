---
title: First login
description: Sign in to the dashboard and finish setting up.
---

:::caution[Draft]
Written from the dashboard's source code. It has not yet been checked page by page against a running dashboard, so a label may differ slightly.
:::


1. Open `http://<this-machine>:3000` from any computer on your home network.
2. Sign in with user `admin`. The password was generated for you: run `sudo heimdall password` (.deb install) or read `secrets/admin_password.txt` in the install folder (script install).
3. Open the **Equipment** page and choose your router, or **Other / not listed (passive mode)** if yours is not in the list. See [Equipment](/manual/equipment/).
4. Leave Heimdall running. It spends a **learning period** getting to know each device before the anomaly detector starts judging them (see [Settings](/manual/settings/)).

:::danger[Do not expose it]
Never forward ports 3000 or 5000 to the internet. To reach Heimdall away from home, use a VPN you already trust.
:::
