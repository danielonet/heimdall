---
title: First login
description: Sign in to the dashboard and finish setting up.
---

1. Open `http://<this-machine>:3000` from any computer on your home network.
2. On a new install the page says **Welcome** and asks you to create your admin account. Choose a user name (3 to 32 letters, digits, dots, dashes or underscores), give the email address a password-reset link should go to, choose a password of at least 12 characters, type it twice, and press **Create account**. You are signed in straight away. Only a salted hash of the password is stored, in Heimdall's database; no password is written to a file. Do this as soon as Heimdall starts: until it is done, anyone who can reach the page could create the account first.

   There is one admin account per Heimdall server. Once it exists, every other computer and phone gets the sign-in page, not account creation.

   :::caution[Set up email, or a forgotten password cannot be reset]
   The **Forgot password?** link on the sign-in page sends its reset link through the email server you set on the [Notifications](/manual/notifications/) page. A new install has none, so until you set one up, no reset email can be sent. Right after creating the account, open **Notifications**, fill in the email (SMTP) settings and press **Send test email** to check it arrives. Without it, the only way back in after forgetting the password is to remove the account on the server and create a new one (see [Troubleshooting](/manual/troubleshooting/#i-forgot-the-admin-user-name-or-password)).
   :::

   Upgrading from a version without the reset email? The old login is removed (the `admin` / `secrets/admin_password.txt` sign-in, and any account created without an email), so this page asks you to create the account again, email included. Your devices, alerts and settings are kept. See [Upgrade](/manual/upgrade/#the-admin-account-is-created-again).
3. Open the **Equipment** page and choose your router, or **Other / not listed (passive mode)** if yours is not in the list. See [Equipment](/manual/equipment/).
4. Still on **Equipment**, check **Network interface**. It must be the network card connected to your home network. If the sensors named ARP Watch, DHCP Watch and Passive Fingerprint show **OFF** on the [Dashboard](/manual/dashboard/), this is a common reason; pick the right one and press **Save**, and they start at once.
5. Leave Heimdall running. It spends a **learning period** getting to know each device before the anomaly detector starts judging them (see [Settings](/manual/settings/)).

:::danger[Do not expose it]
Never forward ports 3000 or 5000 to the internet. To reach Heimdall away from home, use a VPN you already trust.
:::
