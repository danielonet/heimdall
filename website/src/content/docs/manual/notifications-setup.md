---
title: "Guide: set up notifications"
description: "Step-by-step setup of email (with a Gmail example), Telegram and ntfy push notifications."
---

Heimdall can tell you about trouble even when the dashboard is closed. This guide takes each channel from nothing to a working test message. The panel itself is described in [Settings](/manual/settings/).

## What you will receive

All channels get the same two things:

- **An immediate message** the moment a **CRITICAL** alert fires (a confirmed attack, an unknown device, unauthorised access).
- **A daily digest at 7 am** with everything else. On a quiet day it says so, which also tells you Heimdall is still running.

You can use one channel or all three. Leave a channel's fields empty to turn it off. Changes apply at once; there is no restart.

## Which channel?

| Channel | Good for | Alert text leaves your house? | Needs |
|---|---|---|---|
| **ntfy.sh push** | A notification on your phone in a minute, no account | Yes, via ntfy.sh, unless you run your own ntfy server | The free ntfy app |
| **Telegram** | Chat-style alerts you can share with family | Yes, via Telegram's servers | A Telegram account and a bot you create |
| **Email** | A record you keep, and the digest | Yes, via your mail provider | A mail account that allows apps to send |

:::caution
Every one of these sends the *text* of an alert (its title, the device and the advice) through a third party. If you want nothing to leave the house, leave all three empty and use the dashboard. Heimdall is built to run without any notification channel.
:::

## Before any channel: the test buttons

Each channel has a test button on **Settings → Notifications**: **Send test** (ntfy), **Send test message** (Telegram) and **Send test email**. The button sends a short message through the settings you have already **saved**, so the sequence is always: fill in, **Save**, then test. A green line means the message left Heimdall and the service accepted it. A red line gives the reason in plain words and never shows your password, token or topic address.

## Push notifications with ntfy

ntfy is a free notification service. You pick a *topic* name, subscribe to it on your phone, and Heimdall publishes to it.

1. **Install the app.** Search for **ntfy** in the Play Store or App Store, or open `https://ntfy.sh` in a browser for web notifications.
2. **Choose a topic name that nobody can guess.** On the public ntfy.sh server a topic has no password: anyone who knows its name can read it and post to it. Use something long and random, for example `heimdall-k7x2q9vmr4t8`. Do not use `heimdall` or your surname.
3. **Subscribe.** In the app press **+**, enter the topic name, and keep the default server.
4. **Enter it in Heimdall.** On **Settings → Notifications → Push — ntfy.sh**, paste the full address into **Topic URL**, for example `https://ntfy.sh/heimdall-k7x2q9vmr4t8`, then press **Save**.
5. **Press Send test.** The phone should buzz within a few seconds. If it does not, check the topic spelling in the app and in Heimdall: one letter wrong is a different topic.

Notes:

- Use an `https://` address. Heimdall also accepts `http://`, which is only sensible for a server on your own network.
- The topic address is the only secret protecting your feed. Treat it like a password and do not paste it into a screenshot.
- To keep alert text off a third party's server altogether, run your own ntfy server and paste its topic address. The setup is the same; see ntfy's own documentation for running the server.

## Telegram

Heimdall posts through a **bot that you create yourself**. A bot is not a person or a channel: it is an account that only sends and receives messages for a program. Nothing is shared with anyone else, and the bot token is yours.

1. **Create the bot.** In Telegram open a chat with **@BotFather** and send `/newbot`. Choose a display name (for example "Heimdall Alerts") and a unique user name ending in `bot`. BotFather replies with a **token** that looks like `123456789:AAH…`. Treat it like a password.
2. **Decide where the alerts should go.** Either:
   - **A private channel or group (recommended).** Create a new channel, open its settings, choose **Administrators → Add administrator**, search for your bot's user name and add it with permission to **post messages**. A bot cannot post to a channel it is not an administrator of. You can add family members to the channel.
   - **Just you.** Open a chat with your own bot and press **Start** (or send `/start`). A bot can only message a person who has started it first.
3. **Find the destination.**
   - A **public** channel has a link name such as `@myhomealerts`. Use that.
   - A **private** channel or group has a numeric id starting with `-100`. Post any message there, then open `https://api.telegram.org/bot<YOUR TOKEN>/getUpdates` in a browser (replace `<YOUR TOKEN>` with your token) and find `"chat":{"id":-100…`.
   - For **just you**, send a message to the bot and look for `"chat":{"id":` followed by a positive number in the same `getUpdates` page.
   - Anyone who sees that web address sees your token, so never share a screenshot of it.
4. **Enter both in Heimdall.** On **Settings → Notifications → Telegram** paste the **Bot token** and the **Channel or chat**, then press **Save**.
5. **Press Send test message.** A green line means it arrived.

The token is stored in a secret file on the Heimdall machine, not in the database, and is shown as dots afterwards. To replace it, paste a new one and save. To turn Telegram off, clear the channel field and save. On an installation upgraded from an older version, run `sudo heimdall upgrade` (or `./setup.sh` in the install folder) once so the token file exists.

### Telegram errors

| Message | Meaning and fix |
|---|---|
| `Forbidden: the bot can't send messages to the bot` | The chat you entered is a bot, usually your own bot's id. Enter the channel's id or link name, or your *personal* id from step 3. |
| `Forbidden: bot is not a member of the channel chat` | The bot has not been added to the channel as an administrator (step 2). |
| `Forbidden: bot can't initiate conversation with a user` | For a personal chat: open your bot and press **Start** first. |
| `chat not found` | The channel name or id is wrong. A private channel needs the numeric `-100…` id, not a name. |
| `Unauthorized` | The token is wrong or was revoked. Ask BotFather for a new one with `/token`. |

## Email

Heimdall sends mail by SMTP through any provider that lets an app sign in. The settings are the same everywhere:

| Field | What to enter |
|---|---|
| **SMTP server** | Your provider's outgoing server, for example `smtp.gmail.com` |
| **Port** | `587` in nearly every case |
| **STARTTLS** | Ticked. Heimdall supports STARTTLS on port 587. It does **not** support the other style, "SSL" on port 465. |
| **Username** | Usually your full email address |
| **Password** | An app password if the provider offers them, otherwise your mail password |
| **From** | The sender address, normally the same as the username |
| **To** | Where alerts go. Optional: it defaults to **From**, so you mail yourself |

Press **Save**, then **Send test email**. A green line names the address it went to. Check the inbox **and the spam folder** the first time.

### Example: a Google (Gmail) account

Google does not accept your normal password from an app. You need an **app password**.

1. **Turn on 2-Step Verification** at `myaccount.google.com/security`. Google offers app passwords only when it is on. A work or school (Workspace) account may have them disabled by its administrator; if so, use a personal account or another provider.
2. **Create the app password.** Open `myaccount.google.com/apppasswords`, name it "Heimdall" and press **Create**. Google shows 16 letters in four groups **once**. Copy them now. If you lose them, delete that app password and make a new one. If the page does not appear, search "App passwords" in your Google Account search box.
3. **Fill in Heimdall.** On **Settings → Notifications → Email**:

   | Field | Value |
   |---|---|
   | SMTP server | `smtp.gmail.com` |
   | Port | `587` |
   | STARTTLS | ticked |
   | Username | your full Gmail address |
   | Password | the 16 letters (paste them without the spaces) |
   | From | your Gmail address |
   | To | blank, or another address |

4. **Save**, then **Send test email**.

### Email errors

| Message | Meaning and fix |
|---|---|
| The mail server rejected the username or password (535) | With Gmail: you used your normal password, mistyped the app password, or 2-Step Verification is off. Create a new app password. |
| Could not reach the mail server | Wrong server name or port, or the Heimdall machine has no internet. The message names the host and port it tried. |
| The mail server does not support this setting | STARTTLS and the port disagree. Use port 587 with STARTTLS ticked; port 465 (SSL) is not supported. |
| A sender or recipient address was refused | Check **From** and **To**. Many providers only accept a From that matches the signed-in account. |

Other providers work the same way: Outlook uses `smtp-mail.outlook.com`, port 587; most others publish their outgoing server on a help page titled "SMTP settings".

## If nothing arrives

1. Press the channel's test button. If it is red, the message tells you what to fix.
2. If the test is green but real alerts never arrive, remember that only **CRITICAL** alerts are sent immediately. Everything else waits for the 7 am digest.
3. Make sure you pressed **Save** before testing; unsaved edits are not used.
4. For email, check spam. For ntfy, check the topic spelling in the app. For Telegram, check the bot is still an administrator of the channel.
5. See [Troubleshooting](/manual/troubleshooting/) for other problems.
